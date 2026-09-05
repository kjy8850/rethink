import HADevice from './base'
import { Device as Thinq2Device } from '../thinq2/device'
import { DeviceDiscovery, type Connection } from '../homeassistant'
import { type Metadata } from '../thinq'
import { allowExtendedType } from '@/util/casting'
import AABBDevice from './aabb_device'
import log from '@/util/logging'

/*
 * LG Dishwasher H07 (ThinQ modelName "H07", modelId/kind "H07", DeviceType 204,
 * modemType RTK_RTL8720cm).
 *
 * Status: mapped as of 2026-09-05 (web-verified pass). `state` plus 9 settings fields are now
 * backed by real evidence gathered via a controlled LG ThinQ Web test session (see below).
 * Course/Process/RemainTime/Door-by-deliberate-test/etc. remain unconfirmed and stay in
 * `raw_status_record` as a raw diagnostic byte dump.
 *
 * ---- Envelope (confirmed, unchanged from the original stub) ----
 * Wire format is the same "AA [len] ...inner [checksum^0x55] BB" envelope as H11.ts (see
 * aabb_device.ts). Checksum = ((AA + len + sum(inner) + 0x00[checksum-slot] + 0x00[BB-slot])
 * & 0xff) ^ 0x55 -- verified byte-exact against every captured "normal length" frame below
 * (EC/EB/B2/0x00-marker frames). Frames with len byte 0xFF (see "info" frames below) do NOT
 * satisfy this formula -- 0xFF is a length-overflow sentinel for a real length > ~251, and the
 * true checksum algorithm for those extended frames is still unconfirmed; they are left as
 * pure raw passthrough.
 *
 * ---- What IS confirmed (2026-09-05/06 capture: bridge disable+enable cycle, unit idle,
 *       ~14 minutes of natural idle/auto-sleep behavior, no door open and no course run) ----
 *
 * Frame kinds seen after the outer envelope is stripped (buf[0] is always 0x32):
 *   0x32 0xEC -- "doubled" status: payload is exactly two 46-byte halves back-to-back. The
 *                two halves are NOT always identical -- sometimes they capture a real
 *                before/after transition within a single packet (e.g. state flipping from
 *                INITIAL to STANDBY happens between half1 and half2 of one EC frame). We
 *                always take the SECOND half as "current", same convention as H11.
 *   0x32 0xEB -- a single (non-doubled) 46-byte status, byte-identical in layout to one EC
 *                half. Seen once, immediately after a fresh provisioning.
 *   0x32 0xB2 -- a single status with one extra leading 0x00 pad byte (47 bytes total) --
 *                confirmed by direct comparison: B2's payload with the first byte dropped is
 *                byte-identical to the EC half captured in the same burst.
 *   0x32 0x00 -- two different sub-frames sharing this marker, distinguished by byte[2]:
 *                - "26 00" (4-byte inner, i.e. buf = 32 00 26 00): a fixed, content-free
 *                  frame seen exactly twice, ~21s apart, each time immediately BEFORE a burst
 *                  of 0x32 0x0A "info" frames -- looks like a request/trigger for that burst.
 *                - "0B 00 [2 bytes]" (6-byte inner): a frequent (~1/sec) heartbeat whose last
 *                  2 bytes look pseudo-random/non-monotonic across ~15 samples (126036,
 *                  087438, 90EB39, E7B1DC, DB930A, 7F7DB8, EE8B3F, 09F0BF, EBB9C0, 2779C4,
 *                  FE4862 hex) -- not correlated with any status change observed in the same
 *                  window. Purpose unknown (link-layer keepalive/nonce is the best guess).
 *   0x32 0x0A -- a large (137-138 byte) "device info" block containing ASCII part/board
 *                revision strings ("204-1", "DW-1-1", "204-5", ... "204-22") -- clearly a
 *                BOM/component identification frame, not appliance status. Uses the len=0xFF
 *                overflow sentinel (see above). Sent in a dense burst (~once/sec) for about a
 *                minute right after each provisioning/enable cycle, then stops -- consistent
 *                with a one-time handshake/identification exchange, not routine telemetry.
 *                Two near-identical variants alternate (some internal counter/checksum-like
 *                bytes increment by ±1 between them); contents otherwise constant. Left
 *                entirely as raw passthrough -- there is nothing appliance-state-related here.
 *
 * ---- The 46-byte status record (EC-half / EB / B2-minus-pad) ----
 * byte[0]  -- a transport-level toggle bit, observed as 0x00 or 0x08. It flips independently
 *             of the actual content (sometimes both EC halves share the same value, sometimes
 *             not) -- it is NOT part of the appliance status and must be ignored/masked, unlike
 *             H11.ts's `curStatus[0] === 0x00` gate, which would silently drop every other
 *             valid H07 status update if reused here as-is.
 * byte[1]  -- constant 0x18 across every sample. Mirrors H11's curStatus[1] header byte
 *             (H11's header is exactly [0x00, 0x18]); used here only as a framing sanity check.
 * byte[2]  -- **State** (mapped below, see DISHWASHER_STATES). Confirmed by a real observed
 *             transition sequence, chronologically: 0x00 (moments after physical power-on
 *             reset, before cloud registration) -> 0x01 (~1s after `completeProvisioning_ack`)
 *             -> stays 0x01 for ~2.5s while other bytes show transient "self-check" values ->
 *             settles at 0x04 (steady idle, door closed, no job) -> back to 0x00 after ~5
 *             minutes of no interaction. This exactly matches expected real-world behavior
 *             (boot self-test, then standby, then auto power-off/sleep to save the display)
 *             AND lines up with the modelJSON `State` enum's given ordinal order
 *             (POWEROFF/INITIAL/RUNNING/PAUSE/STANDBY/END/POWERFAIL -> 0/1/2/3/4/5/6). Only
 *             codes 0, 1 and 4 were actually observed; 2/3/5/6 are carried over from the
 *             enum order for completeness but are UNCONFIRMED -- any other code renders as
 *             `UNKNOWN(n)` rather than guessing. Re-confirmed 2026-09-05 (POWEROFF -> INITIAL
 *             transition captured again via a real remote power-on through LG ThinQ Web).
 * byte[3]  -- constant 0x00 while idle/STANDBY, observed 0x01 during the transient
 *             post-power-on self-check window (same window where byte[2]=INITIAL). Plausible
 *             reading: Process=NONE(0) vs a transient self-test process code -- still
 *             unconfirmed as a real Process enum since we never started an actual course, so
 *             it is deliberately NOT promoted to its own sensor; visible in `raw_status_record`.
 *
 * ---- Settings fields confirmed 2026-09-05 via a controlled LG ThinQ Web A/B test ----
 * Methodology: logged into the real LG ThinQ account, changed exactly ONE setting at a time
 * on the real physical unit (remote-powered-on for the duration of the test, which requires a
 * real "다음 전원을 켤까요?" confirmation dialog -- confirming this is a deliberate, reversible
 * app-level action, not a physical button press), captured the `raw_status_record` published
 * immediately before and after each change via `ha_get_logs`, diffed byte-for-byte, and
 * reverted every setting back to its original value immediately after capturing the diff. Every
 * field below reproduced cleanly (changed at the exact moment of the app action and nowhere
 * else) and is corroborated by H11.ts having the *exact same bit position* for the semantically
 * equivalent field (H07 and H11 clearly share the same underlying status-record layout beyond
 * just the envelope). Byte numbering below is relative to `raw_status_record` (i.e.
 * data.subarray(2) -- byte[0] here is byte[2] of the full 46-byte record / State).
 *   byte[11] bit 0x10 -- AutoSelect ("건조 옵션 자동 설정" / auto dry option). Same bit as
 *             H11's `auto_dry` (H11 data[11] bit 0x10). A/B tested ON->OFF->ON.
 *   byte[11] bit 0x40 -- wash-complete notification light ("세척 완료 알림등"). Same bit as
 *             H11's `clean_reminder` (H11 data[11] bit 0x40); H07's LG ThinQ Web UI labels it
 *             differently but it is very likely the identical physical LED/feature. A/B
 *             tested OFF->ON->OFF.
 *   byte[11] bit 0x02 -- Door (OPEN when set). NOT deliberately A/B tested (this project's
 *             safety rules forbid opening/closing the door ourselves) -- but a real door-open
 *             event happened to occur mid-session (independently of anything we did): this bit
 *             flipped 0->1 at the same moment the LG ThinQ Web UI started showing "문이 열려
 *             있습니다" (door is open), and it stayed set afterward (consistent with the door
 *             actually being left open in the physical world, not reverting on its own). This
 *             is also the *exact same bit* H11.ts uses for `door` (H11 data[11] bit 0x02).
 *             Given the real observed transition + UI corroboration + cross-model bit-position
 *             match, this is promoted to a confirmed `door` binary_sensor, but flagged here as
 *             passively observed rather than actively tested.
 *   byte[12] -- UNCONFIRMED. Bounced 0x00->0x04 during the post-power-on transient self-check
 *             window (same window as byte[3] above) and back; never seen to move during any
 *             deliberate settings test. Left raw.
 *   byte[13] -- **RinseLevel** ("린스 투입량"). Raw value IS the level number (0-4), matching
 *             the modelJSON enum and the ThinQ Web UI's own labels (0=없음, 1=2cc/약60회,
 *             2=4cc/약30회, 3=5cc/약24회, 4=6cc/약20회). Same byte offset as H11's
 *             `rinse_level` (H11 data[13]). A/B tested 2->4->2.
 *   byte[14] -- **SofteningLevel** ("제품 물 경도 레벨" / water hardness / salt level). Raw
 *             value IS the level number (0-4), matching modelJSON enum and UI labels (0=소금
 *             불필요 ... 4=1주 간격 소금 보충). Same byte offset as H11's `salt_level` (H11
 *             data[14]). A/B tested 1->4->1.
 *   byte[15] bit 0x80 -- BuzzerLevel HIGH ("제품 알림음" Hi), bit 0x40 -- BuzzerLevel LOW (Lo),
 *             neither set -- OFF (꺼짐). Exactly H11's encoding (H11 data[15], same bits,
 *             identical priority order). A/B tested Lo->Hi->Off->Lo (all 3 states confirmed).
 *   byte[15] bit 0x08 -- TimeIndicator ("전면 시간 표시" / front display always-on clock).
 *             Not present in H11.ts. A/B tested ON->OFF->ON.
 *   byte[16] bit 0x04 -- EndAlarmSound ("세척 종료음"). Same bit as H11's `end_alarm_sound`
 *             (H11 data[16] bit 0x04). A/B tested ON->OFF->ON.
 *   byte[19] bit 0x40 -- display brightness ("제품 시간 표시창 밝기", 밝게/어둡게). Same bit as
 *             H11's `brightness` (H11 data[19] bit 0x40). A/B tested Bright->Dim->Bright.
 * NOT tested (deliberately skipped): "원격제어 모드" (DetailRemoteSetting -- 사용 안 함/1회
 * 사용/계속 사용) -- changing this away from "계속 사용" risked disabling further remote
 * control entirely with no remote way back (would require physically touching the unit),
 * so it was left untouched and is not mapped.
 * byte[4..10], byte[17..18], byte[20..45] -- everything else remains unmapped: never moved
 * during any deliberate settings test, and mapping them would require a real course run
 * (RemainTime/Course/Process) which this pass deliberately avoided. Left entirely raw in
 * `raw_status_record` (hex, byte[2] of the full record onward, so State is visible there too
 * for cross-checking) for future reverse engineering once a real course run is captured.
 *
 * ---- Course / SmartCourse tables (fetched fresh 2026-09-06 via GET
 *       /bridge/<id>/modeljson, full Course + SmartCourse sections) ----
 * These are the LG cloud (ThinQ2) command-side course catalog -- they say nothing about local
 * RS485/TLV byte offsets, but they ARE what a real `startCourse` command and any future
 * "current course" status field must ultimately resolve to. `Course` (courseType="Course",
 * directly selectable) below drives the `target_course` select. Full SmartCourse catalog
 * (courseType="SmartCourse", each one an auto-detected preset that maps onto a base Course id
 * plus a fixed option bundle -- e.g. id 5 "Greasy Tableware" -> Course 18 "ONE_HOUR" with
 * ExtraDry=ON) is preserved here for reference, id -> name (English) -> underlying Course id:
 *   2 Pots & Pans (Default)      -> Course 14 (not in the directly-selectable Course dict above
 *                                    -- LG-internal "smart-course-only" course id, unconfirmed)
 *   3 Glass and Wine Glass       -> Course 18 (ONE_HOUR)
 *   4 Grilled Meat               -> Course 2  (INTENSIVE)
 *   5 Greasy Tableware           -> Course 18 (ONE_HOUR)
 *   6 Pressed Tableware          -> Course 14 (see note on id 2)
 *   7 Fish Dish                  -> Course 2  (INTENSIVE)
 *   8 Delicate                   -> Course 18 (ONE_HOUR)
 *   9 Steam Refresh              -> Course 7  (not in the directly-selectable Course dict --
 *                                    likely exists but wasn't in the section we fetched)
 *   10 Rinsing                   -> Course 6  (ditto)
 *   13 Machine Clean             -> Course 9  (ditto -- matches H11's MACHINE_CLEAN=0x09 too)
 *   15 Plastic Wash              -> Course 11 (DOWNLOAD_CYCLE)
 * Not exposed as a component (the task only calls for a Course select) -- kept here purely as
 * research reference for whoever maps SmartCourse selection next.
 *
 * ---- Commands: NOT implemented (by design) ----
 * `target_course`/`start_course`/`cancel_course` components exist so the UI shape is right,
 * but no RS485 command bytes are sent -- byte offsets in the status record are not verified
 * (see above), and H11.ts's write commands (e.g. `F0 26 10 ...`) are H11-specific opcodes that
 * must NOT be assumed to apply to H07's protocol without independent confirmation. The newly
 * added settings components (rinse_level, softening_level, buzzer_level, end_alarm_sound,
 * wash_complete_light, auto_dry, time_indicator, brightness) are READ-ONLY in practice: they
 * mirror H11.ts's sensor/select/switch/number component shapes so the HA UI looks and behaves
 * consistently across both dishwasher models, but `setProperty()` intentionally does not send
 * anything for them either -- confirming the byte OFFSET a value lives at (by reading real
 * app-driven changes) is not the same as confirming the exact WRITE encoding/checksum for a
 * command that sets it, and guessing at a write to a real appliance is out of scope for this
 * pass. Calling setProperty for any of these (or for start/cancel) logs a warning and does
 * nothing, matching the same safety principle used for `initDevice` re-registration.
 *
 * ---- Next steps (see session report) ----
 * 1. Start one real (short) course from the LG panel/app and capture packets through to
 *    completion, to find course/remain-time/option byte offsets (byte[4..10], byte[17..18],
 *    byte[20..45] all remain unmapped).
 * 2. Deliberately capture a door open/close cycle (this pass only observed one passively) to
 *    fully confirm byte[11] bit 0x02 beyond the cross-model + single-observation evidence above.
 * 3. Only once offsets are independently confirmed against real behavior, implement
 *    setProperty()/send() for actual commands.
 */

const DISHWASHER_STATES: Record<number, string> = {
    0: 'POWEROFF', // observed
    1: 'INITIAL', // observed
    2: 'RUNNING', // unconfirmed -- inferred from modelJSON enum order only
    3: 'PAUSE', // unconfirmed -- inferred from modelJSON enum order only
    4: 'STANDBY', // observed
    5: 'END', // unconfirmed -- inferred from modelJSON enum order only
    6: 'POWERFAIL', // unconfirmed -- inferred from modelJSON enum order only
}

// Directly selectable courses (modelJSON `Course` dict, courseType="Course"). id -> name.
const COURSES: Record<number, string> = {
    1: 'AUTO',
    2: 'INTENSIVE',
    5: 'NORMAL/ECO',
    8: 'UPPER_EXPRESS',
    11: 'DOWNLOAD_CYCLE',
    16: 'OVERNIGHT',
    18: 'ONE_HOUR',
}
const COURSE_NAME_TO_ID: Record<string, number> = Object.fromEntries(
    Object.entries(COURSES).map(([id, name]) => [name, Number(id)]),
)

export default class Device extends AABBDevice {
    readonly deviceConfig: DeviceDiscovery

    private frameCount = 0
    private statusFrameCount = 0
    private targetCourseId: number = 1 // AUTO -- staged locally only, never sent

    constructor(HA: Connection, thinq: Thinq2Device, meta: Metadata) {
        super(HA, thinq)
        this.deviceConfig = HADevice.config(meta, { name: 'LG Dishwasher (H07)' })

        this.setConfig(
            allowExtendedType({
                ...this.deviceConfig,
                components: {
                    state: {
                        platform: 'sensor',
                        icon: 'mdi:washing-machine',
                        unique_id: '$deviceid-state',
                        state_topic: '$this/state',
                        name: 'State',
                    },
                    door: {
                        platform: 'binary_sensor',
                        device_class: 'door',
                        unique_id: '$deviceid-door',
                        state_topic: '$this/door',
                        name: 'Door',
                        payload_on: 'OPEN',
                        payload_off: 'CLOSE',
                    },
                    rinse_level: {
                        platform: 'number',
                        icon: 'mdi:water-plus',
                        unique_id: '$deviceid-rinse_level',
                        state_topic: '$this/rinse_level',
                        command_topic: '$this/rinse_level/set',
                        name: 'Rinse Level (not yet functional)',
                        min: 0,
                        max: 4,
                        step: 1,
                    },
                    softening_level: {
                        platform: 'number',
                        icon: 'mdi:shaker',
                        unique_id: '$deviceid-softening_level',
                        state_topic: '$this/softening_level',
                        command_topic: '$this/softening_level/set',
                        name: 'Water Softening Level (not yet functional)',
                        min: 0,
                        max: 4,
                        step: 1,
                    },
                    buzzer_level: {
                        platform: 'select',
                        icon: 'mdi:volume-high',
                        unique_id: '$deviceid-buzzer_level',
                        state_topic: '$this/buzzer_level',
                        command_topic: '$this/buzzer_level/set',
                        name: 'Buzzer Level (not yet functional)',
                        options: ['OFF', 'LOW', 'HIGH'],
                    },
                    end_alarm_sound: {
                        platform: 'switch',
                        icon: 'mdi:music-note',
                        unique_id: '$deviceid-end_alarm_sound',
                        state_topic: '$this/end_alarm_sound',
                        command_topic: '$this/end_alarm_sound/set',
                        name: 'End Alarm Sound (not yet functional)',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    wash_complete_light: {
                        platform: 'switch',
                        icon: 'mdi:lightbulb',
                        unique_id: '$deviceid-wash_complete_light',
                        state_topic: '$this/wash_complete_light',
                        command_topic: '$this/wash_complete_light/set',
                        name: 'Wash Complete Notification Light (not yet functional)',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    auto_dry: {
                        platform: 'switch',
                        icon: 'mdi:weather-sunny',
                        unique_id: '$deviceid-auto_dry',
                        state_topic: '$this/auto_dry',
                        command_topic: '$this/auto_dry/set',
                        name: 'Auto Dry Option (not yet functional)',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    time_indicator: {
                        platform: 'switch',
                        icon: 'mdi:clock-digital',
                        unique_id: '$deviceid-time_indicator',
                        state_topic: '$this/time_indicator',
                        command_topic: '$this/time_indicator/set',
                        name: 'Front Time Display (not yet functional)',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    brightness: {
                        platform: 'switch',
                        icon: 'mdi:brightness-6',
                        unique_id: '$deviceid-brightness',
                        state_topic: '$this/brightness',
                        command_topic: '$this/brightness/set',
                        name: 'Time Display Brightness (not yet functional)',
                        payload_on: 'HIGH',
                        payload_off: 'LOW',
                    },
                    target_course: {
                        platform: 'select',
                        icon: 'mdi:dishwasher',
                        unique_id: '$deviceid-target_course',
                        state_topic: '$this/target_course',
                        command_topic: '$this/target_course/set',
                        name: 'Target Course',
                        options: Object.values(COURSES),
                    },
                    start_course: {
                        platform: 'button',
                        icon: 'mdi:play-circle',
                        unique_id: '$deviceid-start_course',
                        command_topic: '$this/start_course/set',
                        name: 'Start Course (not yet functional)',
                        payload_press: 'PRESS',
                    },
                    cancel_course: {
                        platform: 'button',
                        icon: 'mdi:stop-circle',
                        unique_id: '$deviceid-cancel_course',
                        command_topic: '$this/cancel_course/set',
                        name: 'Cancel Course (not yet functional)',
                        payload_press: 'PRESS',
                    },
                    frame_kind: {
                        platform: 'sensor',
                        icon: 'mdi:tag-outline',
                        unique_id: '$deviceid-frame_kind',
                        state_topic: '$this/frame_kind',
                        name: 'Raw Frame Kind (diagnostic)',
                        entity_category: 'diagnostic',
                    },
                    raw_frame: {
                        platform: 'sensor',
                        icon: 'mdi:code-braces',
                        unique_id: '$deviceid-raw_frame',
                        state_topic: '$this/raw_frame',
                        name: 'Raw Frame Hex (diagnostic, non-status frames)',
                        entity_category: 'diagnostic',
                    },
                    raw_frame_count: {
                        platform: 'sensor',
                        icon: 'mdi:counter',
                        unique_id: '$deviceid-raw_frame_count',
                        state_topic: '$this/raw_frame_count',
                        name: 'Raw Frame Count (diagnostic)',
                        entity_category: 'diagnostic',
                    },
                    raw_status_record: {
                        platform: 'sensor',
                        icon: 'mdi:code-braces',
                        unique_id: '$deviceid-raw_status_record',
                        state_topic: '$this/raw_status_record',
                        name: 'Raw Status Record Hex (diagnostic, unmapped fields)',
                        entity_category: 'diagnostic',
                    },
                    status_frame_count: {
                        platform: 'sensor',
                        icon: 'mdi:counter',
                        unique_id: '$deviceid-status_frame_count',
                        state_topic: '$this/status_frame_count',
                        name: 'Status Frame Count (diagnostic)',
                        entity_category: 'diagnostic',
                    },
                },
            }),
        )
    }

    start() {
        super.start()
        this.publishProperty('target_course', COURSES[this.targetCourseId])
    }

    setProperty(prop: string, mqttValue: string) {
        if (prop === 'target_course') {
            // Staging only -- reflects the selection back to HA, does not send anything.
            if (COURSE_NAME_TO_ID[mqttValue] !== undefined) {
                this.targetCourseId = COURSE_NAME_TO_ID[mqttValue]
                this.publishProperty('target_course', mqttValue)
            }
        } else if (
            prop === 'start_course' ||
            prop === 'cancel_course' ||
            prop === 'rinse_level' ||
            prop === 'softening_level' ||
            prop === 'buzzer_level' ||
            prop === 'end_alarm_sound' ||
            prop === 'wash_complete_light' ||
            prop === 'auto_dry' ||
            prop === 'time_indicator' ||
            prop === 'brightness'
        ) {
            // TODO: not implemented -- byte OFFSETS for these fields are confirmed (see class
            // header, 2026-09-05 web-verified A/B test), but the RS485 WRITE encoding/checksum
            // is not. Sending a guessed write command to a dishwasher (unlike a read) can
            // trigger an unwanted physical action, so this is intentionally a no-op until the
            // write protocol is independently confirmed from real captured commands.
            console.warn(
                `H07: refusing to send '${prop}' -- command encoding not yet implemented/verified (safety guard)`,
            )
            log('status', this.id, `H07: ignored '${prop}' request -- no command sent (unverified protocol)`)
        } else {
            console.warn(`H07: attempted to set '${prop}'='${mqttValue}', but no commands are implemented yet`)
        }
    }

    processAABB(buf: Buffer) {
        if (buf.length < 2 || buf[0] !== 0x32) {
            log('status', this.id, 'H07: unrecognized frame, first byte', buf[0]?.toString(16))
            return
        }

        const marker = buf[1]
        let statusPayload: Buffer | undefined

        if (marker === 0xec) {
            // Doubled payload -- always take the second (freshest) half as current, and don't
            // gate on half[0] (transport toggle bit, see class header).
            const payloadLen = buf.length - 2
            const halfLen = Math.floor(payloadLen / 2)
            if (halfLen > 0) {
                const second = buf.subarray(2 + halfLen, buf.length)
                if (second.length === 46 && second[1] === 0x18) statusPayload = second
            }
        } else if (marker === 0xeb) {
            const body = buf.subarray(2)
            if (body.length === 46 && body[1] === 0x18) statusPayload = body
        } else if (marker === 0xb2) {
            // One extra leading pad byte compared to EB/EC-half -- drop it.
            const body = buf.subarray(3)
            if (body.length === 46 && body[1] === 0x18) statusPayload = body
        }

        if (statusPayload) {
            this.processStatus(statusPayload)
            return
        }

        // Fallback: handshake/info/heartbeat frames (0x00, 0x0A, or a malformed EC/EB/B2 that
        // didn't match the expected 46-byte shape) -- publish as raw diagnostics.
        this.frameCount += 1
        let rawPayload: Buffer
        if (marker === 0xec) {
            const payloadLen = buf.length - 2
            const halfLen = Math.floor(payloadLen / 2)
            rawPayload = halfLen > 0 ? buf.subarray(2 + halfLen, buf.length) : buf.subarray(2)
        } else {
            rawPayload = buf.subarray(2)
        }
        this.publishProperty('frame_kind', '0x' + marker.toString(16).padStart(2, '0'))
        this.publishProperty('raw_frame', rawPayload.toString('hex').toUpperCase())
        this.publishProperty('raw_frame_count', this.frameCount)

        log('status', this.id, 'H07: frame kind', marker.toString(16), 'payload', rawPayload.toString('hex'))
    }

    processStatus(data: Buffer) {
        // data[0] = transport toggle bit (ignored), data[1] = constant 0x18 header byte.
        this.statusFrameCount += 1
        this.publishProperty('status_frame_count', this.statusFrameCount)

        const stateCode = data[2]
        this.publishProperty('state', DISHWASHER_STATES[stateCode] || `UNKNOWN(${stateCode})`)

        // Everything below is relative to raw_status_record, i.e. rsr[i] === data[i + 2].
        const rsr = data.subarray(2)

        // Door (rsr byte[11] bit 0x02) -- see class header: confirmed via one passively
        // observed real transition + cross-model bit-position match with H11, not a
        // deliberate A/B test (we do not open/close the door ourselves).
        this.publishProperty('door', (rsr[11] & 0x02) !== 0 ? 'OPEN' : 'CLOSE')

        // AutoSelect / auto dry option (rsr byte[11] bit 0x10)
        this.publishProperty('auto_dry', (rsr[11] & 0x10) !== 0 ? 'ON' : 'OFF')

        // Wash-complete notification light (rsr byte[11] bit 0x40)
        this.publishProperty('wash_complete_light', (rsr[11] & 0x40) !== 0 ? 'ON' : 'OFF')

        // RinseLevel (rsr byte[13], raw level number 0-4)
        this.publishProperty('rinse_level', rsr[13])

        // SofteningLevel / water hardness (rsr byte[14], raw level number 0-4)
        this.publishProperty('softening_level', rsr[14])

        // BuzzerLevel (rsr byte[15], bit 0x80 = HIGH, bit 0x40 = LOW, neither = OFF)
        let buzzerLevel: string
        if ((rsr[15] & 0x80) !== 0) buzzerLevel = 'HIGH'
        else if ((rsr[15] & 0x40) !== 0) buzzerLevel = 'LOW'
        else buzzerLevel = 'OFF'
        this.publishProperty('buzzer_level', buzzerLevel)

        // TimeIndicator / front display always-on clock (rsr byte[15] bit 0x08)
        this.publishProperty('time_indicator', (rsr[15] & 0x08) !== 0 ? 'ON' : 'OFF')

        // EndAlarmSound (rsr byte[16] bit 0x04)
        this.publishProperty('end_alarm_sound', (rsr[16] & 0x04) !== 0 ? 'ON' : 'OFF')

        // Time display brightness (rsr byte[19] bit 0x40)
        this.publishProperty('brightness', (rsr[19] & 0x40) !== 0 ? 'HIGH' : 'LOW')

        // Everything from byte[2] onward (including the State byte itself, for cross-checking)
        // is also published verbatim -- see class header for the fields that remain unmapped.
        this.publishProperty('raw_status_record', rsr.toString('hex').toUpperCase())
    }
}
