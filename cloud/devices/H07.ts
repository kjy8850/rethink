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
 * Status: PARTIALLY mapped as of 2026-09-06. Only `state` is backed by real evidence; every
 * other field is still exposed as a raw diagnostic byte dump. See the two sections below for
 * exactly what was confirmed and why, and what deliberately was NOT mapped.
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
 *             `UNKNOWN(n)` rather than guessing.
 * byte[3]  -- constant 0x00 in every sample. Structurally this is where H11's `processCode`
 *             lives (curStatus[3] there). Plausible reading: Process=NONE(0), consistent with
 *             an idle unit that never ran a cycle -- but since it never changed, this is an
 *             unconfirmed structural guess, not evidence, so it is deliberately NOT promoted
 *             to its own sensor; it's visible in `raw_status_record` instead.
 * byte[4..45] -- everything else. Some of these bytes did change during the observed
 *             boot-sequence transient (e.g. byte[7]/[8]/[13]/[14]/[18]/[22] all moved together
 *             while State sat at INITIAL, then reverted once State reached STANDBY), which
 *             hints they may be self-test/default-course-preview fields -- but with no real
 *             course ever started, no door ever opened, and no way to distinguish
 *             "course/time/door/rinse/salt/etc." from "self-test scratch values" among them,
 *             mapping any of them individually would be a guess. They are left entirely raw
 *             in `raw_status_record` (hex, byte[2] onward, so State is visible there too for
 *             cross-checking) for future reverse engineering once real events are captured.
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
 * must NOT be assumed to apply to H07's protocol without independent confirmation. Calling
 * setProperty for start/cancel logs a warning and does nothing, matching the same safety
 * principle used for `initDevice` re-registration.
 *
 * ---- Next steps (see session report) ----
 * 1. Capture a real door-open/close event while this handler is active, to find the door bit.
 * 2. Start one real (short) course from the LG panel/app and capture packets through to
 *    completion, to find course/remain-time/rinse/salt/option byte offsets.
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
        } else if (prop === 'start_course' || prop === 'cancel_course') {
            // TODO: not implemented -- RS485 command bytes for H07 are not verified against
            // the real device yet (see class header). Sending a guessed command to a
            // dishwasher (unlike a read) can trigger an unwanted physical action, so this is
            // intentionally a no-op until offsets are confirmed from real captured cycles.
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

        // Everything from byte[2] onward (including the State byte itself, for cross-checking)
        // is published verbatim -- see class header for the fields that remain unmapped.
        this.publishProperty('raw_status_record', data.subarray(2).toString('hex').toUpperCase())
    }
}
