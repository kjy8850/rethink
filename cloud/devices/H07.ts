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
 * Status: read AND write mapped as of 2026-09-08. The 2026-09-05 pass (below) confirmed `state`
 * plus 9 settings fields via a controlled LG ThinQ Web session; the 2026-09-08 pass added
 * Process/Course/times/delay-start and, crucially, the WRITE protocol -- captured from real LG
 * ThinQ app commands as they passed through this bridge.
 *
 * ---- Write protocol (captured 2026-09-08, every checksum verified byte-exact) ----
 * Commands arrive from the LG cloud and appear in the log as `bridge <id> <- AA..BB` (the `->`
 * direction is device-to-cloud status; reading only `incoming` lines misses commands entirely).
 * They use the same envelope as status frames, with inner payload `F0 26 <opcode> [args]`:
 *
 *   F0 26 10 [Course][DelayHour][00][opt3][opt4][00] -- start course   (observed 4x)
 *   F0 26 11                                         -- cancel / drain stop (3x)
 *   F0 26 12                                         -- power off      (3x)
 *   F0 26 13                                         -- pause          (4x)
 *   F0 26 14                                         -- resume         (4x)
 *   F0 26 16                                         -- power on/wake  (3x)
 *   F0 26 [Rinse][Softening][opt1][opt2][opt3] 00 00 00 -- settings    (28x)
 *   F0 25 [Slot][00][BaseCourse][SmartCourse][00][00][opt3][opt4][00 x7]
 *                                                    -- write one download slot (1x)
 *
 * The F0 26 opcodes are the ones H11.ts already sends, so the two models share the command layer
 * as well as the status layout. F0 25 has no H11 counterpart. Where H07 differs from H11:
 *   - settings opt1 bit 0x10 is the front time display (H11 has no bit there; H11's 0x08 is its
 *     clean reminder). Verified by A/B: toggling it in the app moved rsr[15] bit 0x08.
 *   - a downloaded cycle is selected by SLOT in opt4 bits 5-6 (0x00/0x20/0x40 for slots 1/2/3),
 *     not by any flag meaning "this is a download". Slot 3 kept 0x40 across a change of what it
 *     held, which is what pins this down. H11 instead has a single opt4 0x40 download flag.
 *
 * Start-command option bytes, all four captured smart-course starts agreeing exactly with the
 * option defaults modelJSON lists for that course:
 *   opt3 0x80 = Steam, 0x04 = ExtraDry (0x08 = HighTemp carried over from H11, never seen here)
 *   opt4 0x08/0x10/0x18 = extra rinse 1/2/3 (from H11, never seen here), bits 5-6 = download slot
 * An earlier reading of this file called opt3 0x80 a "downloaded cycle" marker, off one capture
 * where steam happened to be on. A later download start (RINSING, which defaults to no options)
 * carried opt3 0x00 and disproved it.
 *
 * What was directly verified on this unit: every opcode above; rinse and softening levels across
 * their full 0..4 range; buzzer OFF/LOW/HIGH; end alarm sound; front time display; display
 * brightness; delay start at two different hour values; four smart courses and their base/option
 * bytes; one slot rewrite. What is ASSUMED from H11 and NOT tested here: opt3 0x08 (high temp),
 * the opt4 extra-rinse levels, settings opt1 bit 0x08 (wash-complete light), and the two
 * non-PERMANENT remote-start modes -- only PERMANENT (opt2 0x80) was ever seen.
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
 * ---- Status record, 2026-09-08 additions ----
 * The first eleven bytes turned out to follow modelJSON's `Monitoring.protocol` field order
 * exactly: state, process, error, initialTimeH, initialTimeM, course, courseType, remainTimeH,
 * remainTimeM, reserveTimeH, reserveTimeM. All confirmed against real runs:
 *   byte[1]  Process   -- 0=NONE, 1=RESERVED, 2=RUNNING, 0x63=cancel/drain.
 *   byte[3,4]  Initial_Time H:M  -- 2:12, 1:46 and 2:08 for three different courses.
 *   byte[5]  Course    -- matches the course byte of the start command that produced it.
 *   byte[6]  CourseType -- 1 while a smart course is loaded, 0 for a plain course.
 *   byte[7,8]  Remain_Time H:M   -- drops to 0:01 on cancel, and the unit really does return
 *              to INITIAL exactly one minute later (seen three times).
 *   byte[9,10] Reserve_Time H:M  -- a 3-hour delay start shows 3:00 and counts down 1/min.
 *   byte[12] mirrors the start command's opt3, plus bit 0x01 while a delay start is armed.
 *   byte[20] SmartCourse -- 5 (GREASY_TABLEWARE) while that downloaded course ran.
 *
 * ---- Still unmapped / unverified ----
 * 1. opt3/opt4 course option bits and settings opt1 bit 0x08 -- carried over from H11 (see the
 *    write-protocol note above); A/B each one on this unit to promote them from "assumed".
 * 2. byte[11] bit 0x08 toggles during cancel/drain; byte[21] is 0x10 for the upper-express
 *    course while the start command's opt4 was 0x08. Both still unexplained.
 * 3. byte[17,18] and byte[22..45] are untouched by anything tried so far.
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

/*
 * modelJSON `SmartCourse` dict, reported in rsr[20]. `base` is that entry's own `Course` field:
 * a smart course rides on a plain course, and the appliance reports that base id in rsr[5].
 * Confirmed against four real selections (5->18, 13->9, 10->6, 6->14), all exact.
 *
 * `opt3` is the option byte the LG app sends for that course, derived from the same entry's
 * `function` defaults: Steam -> 0x80, ExtraDry -> 0x04. Also confirmed four times.
 *
 * `writable` is false where the entry defaults to something this driver cannot encode yet --
 * ExtraRinseLevel or a non-zero SprayForce. Those most likely live in the seven trailing bytes
 * of the download frame (six SprayForce fields, seven spare bytes), but no capture has ever
 * shown one non-zero, so writing those two courses is refused rather than guessed.
 */
const SMART_COURSES: Record<number, { name: string; base: number; opt3: number; writable: boolean }> = {
    2: { name: 'POTS_PANS', base: 14, opt3: 0x84, writable: true },
    3: { name: 'GLASS_AND_WINE_GLASS', base: 18, opt3: 0x80, writable: false }, // ExtraRinse + SprayForce
    4: { name: 'GRILLED_MEAT', base: 2, opt3: 0x04, writable: true },
    5: { name: 'GREASY_TABLEWARE', base: 18, opt3: 0x04, writable: true }, // observed
    6: { name: 'PRESSED_TABLEWARE', base: 14, opt3: 0x04, writable: true }, // observed
    7: { name: 'FISH_DISH', base: 2, opt3: 0x84, writable: true },
    8: { name: 'DELICATE', base: 18, opt3: 0x00, writable: false }, // SprayForce
    9: { name: 'STEAM_REFRESH', base: 7, opt3: 0x80, writable: true },
    10: { name: 'RINSING', base: 6, opt3: 0x00, writable: true }, // observed
    13: { name: 'MACHINE_CLEAN', base: 9, opt3: 0x80, writable: true }, // observed
    15: { name: 'PLASTIC_WASH', base: 11, opt3: 0x00, writable: true },
}
const SMART_COURSE_NAME_TO_ID: Record<string, number> = Object.fromEntries(
    Object.entries(SMART_COURSES).map(([id, c]) => [c.name, Number(id)]),
)

function smartCourseName(code: number): string {
    return SMART_COURSES[code]?.name || `DOWNLOAD_COURSE(${code})`
}

// rsr[1]. 0/1/2 observed directly; 3..7 follow the modelJSON `Process` enum order and are
// UNCONFIRMED. 0x63 breaks that order but is what the unit really reports while draining
// after a cancel (observed three times), so it is listed explicitly rather than as ordinal 8.
const PROCESSES: Record<number, string> = {
    0: 'NONE', // observed
    1: 'RESERVED', // observed (delay start armed)
    2: 'RUNNING', // observed
    3: 'RINSING', // unconfirmed -- enum order only
    4: 'DRYING', // unconfirmed -- enum order only
    5: 'END', // unconfirmed -- enum order only
    6: 'NIGHTDRY', // unconfirmed -- enum order only
    7: 'COOLDRY', // unconfirmed -- enum order only
    0x63: 'CANCEL', // observed
}

export default class Device extends AABBDevice {
    readonly deviceConfig: DeviceDiscovery

    private frameCount = 0
    private statusFrameCount = 0

    // Staged locally, only sent when `start_course` is pressed.
    private targetCourseId: number = 1 // AUTO
    private targetDelay: number = 0
    private targetHighTemp: boolean = false
    private targetExtraDry: boolean = false
    private targetSteam: boolean = false
    private targetExtraRinse: number = 0
    private targetDownloadSlot: number = 1 // which of the three slots DOWNLOAD_CYCLE runs

    // Staged for `download_course`, which rewrites one slot rather than starting anything.
    private targetDownloadCourse: string = 'GREASY_TABLEWARE'

    // The settings command carries every setting at once, so the current values have to be
    // kept around and re-sent whenever any single one changes. They are refreshed from every
    // status record, so these initial values only matter before the first record arrives.
    private cachedRinseLevel: number = 2
    private cachedSofteningLevel: number = 1
    private cachedBuzzerLevel: string = 'LOW'
    private cachedEndAlarmSound: boolean = true
    private cachedAutoDry: boolean = true
    private cachedTimeIndicator: boolean = true
    private cachedWashCompleteLight: boolean = false
    private cachedBrightness: boolean = true
    private cachedRemoteStartMode: string = 'PERMANENT'

    constructor(HA: Connection, thinq: Thinq2Device, meta: Metadata) {
        super(HA, thinq)
        this.deviceConfig = HADevice.config(meta, { name: 'LG Dishwasher (H07)' })

        this.setConfig(
            allowExtendedType({
                ...this.deviceConfig,
                components: {
                    power: {
                        platform: 'switch',
                        icon: 'mdi:power',
                        unique_id: '$deviceid-power',
                        state_topic: '$this/power',
                        command_topic: '$this/power/set',
                        name: 'Power',
                    },
                    state: {
                        platform: 'sensor',
                        icon: 'mdi:washing-machine',
                        unique_id: '$deviceid-state',
                        state_topic: '$this/state',
                        name: 'State',
                    },
                    process: {
                        platform: 'sensor',
                        icon: 'mdi:progress-clock',
                        unique_id: '$deviceid-process',
                        state_topic: '$this/process',
                        name: 'Process',
                    },
                    course: {
                        platform: 'sensor',
                        icon: 'mdi:dishwasher',
                        unique_id: '$deviceid-course',
                        state_topic: '$this/course',
                        name: 'Course',
                    },
                    course_time: {
                        platform: 'sensor',
                        icon: 'mdi:timer',
                        unique_id: '$deviceid-course_time',
                        state_topic: '$this/course_time',
                        name: 'Course Time',
                        unit_of_measurement: 'min',
                    },
                    remain_time: {
                        platform: 'sensor',
                        icon: 'mdi:timer-sand',
                        unique_id: '$deviceid-remain_time',
                        state_topic: '$this/remain_time',
                        name: 'Remain Time',
                        unit_of_measurement: 'min',
                    },
                    reserve_time: {
                        platform: 'sensor',
                        icon: 'mdi:clock-fast',
                        unique_id: '$deviceid-reserve_time',
                        state_topic: '$this/reserve_time',
                        name: 'Delay Start Remaining',
                        unit_of_measurement: 'min',
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
                        name: 'Rinse Level',
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
                        name: 'Water Softening Level',
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
                        name: 'Buzzer Level',
                        options: ['OFF', 'LOW', 'HIGH'],
                    },
                    end_alarm_sound: {
                        platform: 'switch',
                        icon: 'mdi:music-note',
                        unique_id: '$deviceid-end_alarm_sound',
                        state_topic: '$this/end_alarm_sound',
                        command_topic: '$this/end_alarm_sound/set',
                        name: 'End Alarm Sound',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    wash_complete_light: {
                        platform: 'switch',
                        icon: 'mdi:lightbulb',
                        unique_id: '$deviceid-wash_complete_light',
                        state_topic: '$this/wash_complete_light',
                        command_topic: '$this/wash_complete_light/set',
                        name: 'Wash Complete Notification Light',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    auto_dry: {
                        platform: 'switch',
                        icon: 'mdi:weather-sunny',
                        unique_id: '$deviceid-auto_dry',
                        state_topic: '$this/auto_dry',
                        command_topic: '$this/auto_dry/set',
                        name: 'Auto Dry Option',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    time_indicator: {
                        platform: 'switch',
                        icon: 'mdi:clock-digital',
                        unique_id: '$deviceid-time_indicator',
                        state_topic: '$this/time_indicator',
                        command_topic: '$this/time_indicator/set',
                        name: 'Front Time Display',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    brightness: {
                        platform: 'switch',
                        icon: 'mdi:brightness-6',
                        unique_id: '$deviceid-brightness',
                        state_topic: '$this/brightness',
                        command_topic: '$this/brightness/set',
                        name: 'Time Display Brightness',
                        payload_on: 'HIGH',
                        payload_off: 'LOW',
                    },
                    remote_start_mode: {
                        platform: 'select',
                        icon: 'mdi:remote',
                        unique_id: '$deviceid-remote_start_mode',
                        state_topic: '$this/remote_start_mode',
                        command_topic: '$this/remote_start_mode/set',
                        name: 'Remote Start Mode',
                        options: ['PERMANENT', 'ONE_TIME', 'OFF'],
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
                    target_delay: {
                        platform: 'number',
                        icon: 'mdi:clock-start',
                        unique_id: '$deviceid-target_delay',
                        state_topic: '$this/target_delay',
                        command_topic: '$this/target_delay/set',
                        name: 'Delay Start Hour',
                        min: 0,
                        max: 12,
                        step: 1,
                    },
                    target_high_temp: {
                        platform: 'switch',
                        icon: 'mdi:thermometer-high',
                        unique_id: '$deviceid-target_high_temp',
                        state_topic: '$this/target_high_temp',
                        command_topic: '$this/target_high_temp/set',
                        name: 'High Temp',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    target_extra_dry: {
                        platform: 'switch',
                        icon: 'mdi:weather-sunny',
                        unique_id: '$deviceid-target_extra_dry',
                        state_topic: '$this/target_extra_dry',
                        command_topic: '$this/target_extra_dry/set',
                        name: 'Extra Dry',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    target_steam: {
                        platform: 'switch',
                        icon: 'mdi:kettle-steam',
                        unique_id: '$deviceid-target_steam',
                        state_topic: '$this/target_steam',
                        command_topic: '$this/target_steam/set',
                        name: 'Steam',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    target_extra_rinse: {
                        platform: 'select',
                        icon: 'mdi:water-plus',
                        unique_id: '$deviceid-target_extra_rinse',
                        state_topic: '$this/target_extra_rinse',
                        command_topic: '$this/target_extra_rinse/set',
                        name: 'Extra Rinse',
                        options: ['0', '1', '2', '3'],
                    },
                    target_download_slot: {
                        platform: 'select',
                        icon: 'mdi:numeric',
                        unique_id: '$deviceid-target_download_slot',
                        state_topic: '$this/target_download_slot',
                        command_topic: '$this/target_download_slot/set',
                        name: 'Download Slot',
                        options: ['1', '2', '3'],
                    },
                    current_download_course: {
                        platform: 'sensor',
                        icon: 'mdi:download-circle',
                        unique_id: '$deviceid-current_download_course',
                        state_topic: '$this/current_download_course',
                        name: 'Current Download Course',
                    },
                    download_slot_1: {
                        platform: 'sensor',
                        icon: 'mdi:numeric-1-circle',
                        unique_id: '$deviceid-download_slot_1',
                        state_topic: '$this/download_slot_1',
                        name: 'Download Slot 1',
                    },
                    download_slot_2: {
                        platform: 'sensor',
                        icon: 'mdi:numeric-2-circle',
                        unique_id: '$deviceid-download_slot_2',
                        state_topic: '$this/download_slot_2',
                        name: 'Download Slot 2',
                    },
                    download_slot_3: {
                        platform: 'sensor',
                        icon: 'mdi:numeric-3-circle',
                        unique_id: '$deviceid-download_slot_3',
                        state_topic: '$this/download_slot_3',
                        name: 'Download Slot 3',
                    },
                    target_download_course: {
                        platform: 'select',
                        icon: 'mdi:download',
                        unique_id: '$deviceid-target_download_course',
                        state_topic: '$this/target_download_course',
                        command_topic: '$this/target_download_course/set',
                        name: 'Course To Download',
                        options: Object.values(SMART_COURSES)
                            .filter((c) => c.writable)
                            .map((c) => c.name),
                    },
                    download_course: {
                        platform: 'button',
                        icon: 'mdi:download-box',
                        unique_id: '$deviceid-download_course',
                        command_topic: '$this/download_course/set',
                        name: 'Write Course Into Slot',
                        payload_press: 'PRESS',
                    },
                    start_course: {
                        platform: 'button',
                        icon: 'mdi:play-circle',
                        unique_id: '$deviceid-start_course',
                        command_topic: '$this/start_course/set',
                        name: 'Start Course',
                        payload_press: 'PRESS',
                    },
                    pause_course: {
                        platform: 'button',
                        icon: 'mdi:pause-circle',
                        unique_id: '$deviceid-pause_course',
                        command_topic: '$this/pause_course/set',
                        name: 'Pause Course',
                        payload_press: 'PRESS',
                    },
                    resume_course: {
                        platform: 'button',
                        icon: 'mdi:play-pause',
                        unique_id: '$deviceid-resume_course',
                        command_topic: '$this/resume_course/set',
                        name: 'Resume Course',
                        payload_press: 'PRESS',
                    },
                    cancel_course: {
                        platform: 'button',
                        icon: 'mdi:stop-circle',
                        unique_id: '$deviceid-cancel_course',
                        command_topic: '$this/cancel_course/set',
                        name: 'Cancel Course / Drain Stop',
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
        this.publishProperty('target_delay', this.targetDelay)
        this.publishProperty('target_high_temp', this.targetHighTemp ? 'ON' : 'OFF')
        this.publishProperty('target_extra_dry', this.targetExtraDry ? 'ON' : 'OFF')
        this.publishProperty('target_steam', this.targetSteam ? 'ON' : 'OFF')
        this.publishProperty('target_extra_rinse', String(this.targetExtraRinse))
        this.publishProperty('target_download_slot', String(this.targetDownloadSlot))
        this.publishProperty('target_download_course', this.targetDownloadCourse)
    }

    // The unit has no per-setting write: every settings command carries the full set, so this
    // always sends the cached values (refreshed from each status record) with one field changed.
    // Layout captured 2026-09-08, 28 frames, each one matched against the resulting status diff.
    sendSettings() {
        let opt1 = 0x00
        if (this.cachedEndAlarmSound) opt1 |= 0x40 // verified
        if (this.cachedAutoDry) opt1 |= 0x20 // matches status, not A/B tested on its own
        if (this.cachedTimeIndicator) opt1 |= 0x10 // verified -- H11 has no bit here
        if (this.cachedWashCompleteLight) opt1 |= 0x08 // ASSUMED from H11's clean_reminder bit
        if (this.cachedBuzzerLevel === 'HIGH')
            opt1 |= 0x04 // verified
        else if (this.cachedBuzzerLevel === 'LOW') opt1 |= 0x02 // verified

        // Only PERMANENT (0x80) was ever observed on this unit; the other two come from H11.
        let opt2 = 0x00
        if (this.cachedRemoteStartMode === 'OFF') opt2 = 0xc0
        else if (this.cachedRemoteStartMode === 'PERMANENT') opt2 = 0x80
        else if (this.cachedRemoteStartMode === 'ONE_TIME') opt2 = 0x40

        let opt3 = 0x00
        if (this.cachedBrightness) opt3 |= 0x40 // verified

        this.send(
            Buffer.from([
                0xf0,
                0x26,
                this.cachedRinseLevel,
                this.cachedSofteningLevel,
                opt1,
                opt2,
                opt3,
                0x00,
                0x00,
                0x00,
            ]),
        )
    }

    /*
     * opt3: the course option byte. 0x80=Steam and 0x04=ExtraDry are confirmed -- every one of
     * the four captured smart-course starts carried exactly the option defaults modelJSON lists
     * for that course. 0x08=HighTemp is carried over from H11 and never seen on this unit.
     *
     * Note 0x80 is Steam and NOT a "downloaded cycle" marker, despite a single early capture
     * where a download start happened to have it set: a later download start (RINSING, which
     * defaults to no options at all) carried opt3 0x00.
     */
    private optionByte(): number {
        let opt3 = 0x00
        if (this.targetSteam) opt3 |= 0x80
        if (this.targetHighTemp) opt3 |= 0x08
        if (this.targetExtraDry) opt3 |= 0x04
        return opt3
    }

    /*
     * opt4: extra-rinse level in the low bits, and for DOWNLOAD_CYCLE the slot to run in bits
     * 5-6. Slots 1/2/3 were seen as 0x00/0x20/0x40, and slot 3 kept 0x40 after its contents were
     * replaced -- so this selects the slot, not the course sitting in it.
     */
    private rinseAndSlotByte(): number {
        let opt4 = 0x00
        if (this.targetExtraRinse === 1) opt4 |= 0x08
        else if (this.targetExtraRinse === 2) opt4 |= 0x10
        else if (this.targetExtraRinse === 3) opt4 |= 0x18
        if (this.targetCourseId === 0x0b) opt4 |= (this.targetDownloadSlot - 1) << 5
        return opt4
    }

    setProperty(prop: string, mqttValue: string) {
        switch (prop) {
            // ---- direct commands (opcodes captured 2026-09-08, checksums verified) ----
            case 'power':
                this.send(Buffer.from(mqttValue === 'ON' ? 'F02616' : 'F02612', 'hex'))
                return
            case 'pause_course':
                this.send(Buffer.from('F02613', 'hex'))
                return
            case 'resume_course':
                this.send(Buffer.from('F02614', 'hex'))
                return
            case 'cancel_course':
                this.send(Buffer.from('F02611', 'hex'))
                return

            // ---- staged course parameters (nothing is sent until start_course) ----
            case 'target_course':
                if (COURSE_NAME_TO_ID[mqttValue] !== undefined) {
                    this.targetCourseId = COURSE_NAME_TO_ID[mqttValue]
                    this.publishProperty('target_course', mqttValue)
                }
                return
            case 'target_delay': {
                const val = parseInt(mqttValue, 10)
                if (!isNaN(val)) {
                    this.targetDelay = val
                    this.publishProperty('target_delay', val)
                }
                return
            }
            case 'target_high_temp':
                this.targetHighTemp = mqttValue === 'ON'
                this.publishProperty('target_high_temp', mqttValue)
                return
            case 'target_extra_dry':
                this.targetExtraDry = mqttValue === 'ON'
                this.publishProperty('target_extra_dry', mqttValue)
                return
            case 'target_steam':
                this.targetSteam = mqttValue === 'ON'
                this.publishProperty('target_steam', mqttValue)
                return
            case 'target_extra_rinse': {
                const val = parseInt(mqttValue, 10)
                if (!isNaN(val)) {
                    this.targetExtraRinse = val
                    this.publishProperty('target_extra_rinse', mqttValue)
                }
                return
            }

            // ---- F0 26 10 [Course][DelayHour][00][opt3][opt4][00] ----
            case 'start_course':
                this.send(
                    Buffer.from([
                        0xf0,
                        0x26,
                        0x10,
                        this.targetCourseId,
                        this.targetDelay,
                        0x00,
                        this.optionByte(),
                        this.rinseAndSlotByte(),
                        0x00,
                    ]),
                )
                return

            case 'target_download_slot': {
                const val = parseInt(mqttValue, 10)
                if (val >= 1 && val <= 3) {
                    this.targetDownloadSlot = val
                    this.publishProperty('target_download_slot', mqttValue)
                }
                return
            }
            case 'target_download_course':
                if (SMART_COURSE_NAME_TO_ID[mqttValue] !== undefined) {
                    this.targetDownloadCourse = mqttValue
                    this.publishProperty('target_download_course', mqttValue)
                }
                return

            // ---- F0 25 [Slot][00][BaseCourse][SmartCourse][00][00][opt3][opt4][00 x7] ----
            // Rewrites what one of the three download slots holds. Captured once, byte-exact:
            // slot 3 <- PRESSED_TABLEWARE produced `03 00 0E 06 00 00 04 40` + seven zero bytes,
            // and the slot byte in the status record followed two seconds later. Nothing has to
            // be started for this to take effect.
            case 'download_course': {
                const id = SMART_COURSE_NAME_TO_ID[this.targetDownloadCourse]
                const course = id === undefined ? undefined : SMART_COURSES[id]
                if (!course || !course.writable) {
                    console.warn(
                        `H07: refusing to download '${this.targetDownloadCourse}' -- its option defaults ` +
                            `(extra rinse / spray force) have no confirmed encoding in this frame`,
                    )
                    log('status', this.id, `H07: download of '${this.targetDownloadCourse}' refused (unverified)`)
                    return
                }
                const slot = this.targetDownloadSlot
                this.send(
                    Buffer.from([
                        0xf0,
                        0x25,
                        slot,
                        0x00,
                        course.base,
                        id,
                        0x00,
                        0x00,
                        course.opt3,
                        (slot - 1) << 5,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                    ]),
                )
                return
            }

            // ---- settings (whole set re-sent each time) ----
            case 'rinse_level': {
                const val = parseInt(mqttValue, 10)
                if (!isNaN(val)) {
                    this.cachedRinseLevel = val
                    this.sendSettings()
                }
                return
            }
            case 'softening_level': {
                const val = parseInt(mqttValue, 10)
                if (!isNaN(val)) {
                    this.cachedSofteningLevel = val
                    this.sendSettings()
                }
                return
            }
            case 'buzzer_level':
                this.cachedBuzzerLevel = mqttValue
                this.sendSettings()
                return
            case 'end_alarm_sound':
                this.cachedEndAlarmSound = mqttValue === 'ON'
                this.sendSettings()
                return
            case 'auto_dry':
                this.cachedAutoDry = mqttValue === 'ON'
                this.sendSettings()
                return
            case 'time_indicator':
                this.cachedTimeIndicator = mqttValue === 'ON'
                this.sendSettings()
                return
            case 'wash_complete_light':
                this.cachedWashCompleteLight = mqttValue === 'ON'
                this.sendSettings()
                return
            case 'brightness':
                this.cachedBrightness = mqttValue === 'HIGH'
                this.sendSettings()
                return
            case 'remote_start_mode':
                this.cachedRemoteStartMode = mqttValue
                this.sendSettings()
                return

            default:
                console.warn(`H07: attempted to set unknown property '${prop}'='${mqttValue}'`)
                log('status', this.id, `H07: ignored unknown property '${prop}'`)
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

        // Process (rsr byte[1]). Note a delay-started job reports State=RUNNING *and*
        // Process=RESERVED -- the unit is only counting down, not washing yet.
        const processCode = rsr[1]
        this.publishProperty('process', PROCESSES[processCode] || `UNKNOWN(${processCode})`)

        // Unlike H11, a cancel/drain (process 0x63) is NOT reported as powered off here: the
        // unit really is still awake and draining, and flipping the switch off and back on a
        // minute later is worse than leaving it on.
        this.publishProperty('power', stateCode === 0 || stateCode === 4 ? 'OFF' : 'ON')

        // Course (rsr byte[5]) with the downloaded course (rsr byte[20]) taking precedence,
        // same convention as H11. Every course value ever observed (0x08/0x10/0x12) is a real
        // modelJSON `Course` id, and 0x08/0x10 matched what was picked in the app.
        // The course byte is cleared to 0 while powered off and during a cancel, which is a
        // normal idle reading rather than an unrecognized code -- report it as NONE. (It is
        // deliberately not in COURSES, since that map also supplies the selectable options.)
        const smartCourseCode = rsr[20]
        const baseCourseCode = rsr[5]
        let courseStr: string
        if (smartCourseCode !== 0) {
            courseStr = smartCourseName(smartCourseCode)
        } else if (baseCourseCode === 0) {
            courseStr = 'NONE'
        } else {
            courseStr = COURSES[baseCourseCode] || `COURSE(${baseCourseCode})`
        }
        this.publishProperty('course', courseStr)

        // The three download slots and whichever of them is currently selected. rsr[24..26] were
        // read as 05/0D/0A -- the exact three courses the appliance offered -- and rsr[26] flipped
        // 0A -> 06 two seconds after a slot was rewritten from the app.
        this.publishProperty('current_download_course', rsr[23] === 0 ? 'NONE' : smartCourseName(rsr[23]))
        for (let slot = 1; slot <= 3; slot++) {
            const code = rsr[23 + slot]
            this.publishProperty(`download_slot_${slot}`, code === 0 ? 'NONE' : smartCourseName(code))
        }

        // Initial / remaining / delay-start times, each an (hour, minute) pair.
        this.publishProperty('course_time', rsr[3] * 60 + rsr[4])
        this.publishProperty('remain_time', rsr[7] * 60 + rsr[8])
        this.publishProperty('reserve_time', rsr[9] * 60 + rsr[10])

        // Door (rsr byte[11] bit 0x02) -- confirmed 2026-09-08 against a deliberate sequence of
        // door open/close events, and steady across every course run.
        this.publishProperty('door', (rsr[11] & 0x02) !== 0 ? 'OPEN' : 'CLOSE')

        // AutoSelect / auto dry option (rsr byte[11] bit 0x10)
        this.cachedAutoDry = (rsr[11] & 0x10) !== 0
        this.publishProperty('auto_dry', this.cachedAutoDry ? 'ON' : 'OFF')

        // Wash-complete notification light (rsr byte[11] bit 0x40)
        this.cachedWashCompleteLight = (rsr[11] & 0x40) !== 0
        this.publishProperty('wash_complete_light', this.cachedWashCompleteLight ? 'ON' : 'OFF')

        // RinseLevel (rsr byte[13], raw level number 0-4)
        this.cachedRinseLevel = rsr[13]
        this.publishProperty('rinse_level', this.cachedRinseLevel)

        // SofteningLevel / water hardness (rsr byte[14], raw level number 0-4)
        this.cachedSofteningLevel = rsr[14]
        this.publishProperty('softening_level', this.cachedSofteningLevel)

        // BuzzerLevel (rsr byte[15], bit 0x80 = HIGH, bit 0x40 = LOW, neither = OFF)
        if ((rsr[15] & 0x80) !== 0) this.cachedBuzzerLevel = 'HIGH'
        else if ((rsr[15] & 0x40) !== 0) this.cachedBuzzerLevel = 'LOW'
        else this.cachedBuzzerLevel = 'OFF'
        this.publishProperty('buzzer_level', this.cachedBuzzerLevel)

        // TimeIndicator / front display always-on clock (rsr byte[15] bit 0x08)
        this.cachedTimeIndicator = (rsr[15] & 0x08) !== 0
        this.publishProperty('time_indicator', this.cachedTimeIndicator ? 'ON' : 'OFF')

        // EndAlarmSound (rsr byte[16] bit 0x04)
        this.cachedEndAlarmSound = (rsr[16] & 0x04) !== 0
        this.publishProperty('end_alarm_sound', this.cachedEndAlarmSound ? 'ON' : 'OFF')

        // RemoteStartMode (rsr byte[16] bits 0xC0), same encoding as the command's opt2.
        const remoteBits = rsr[16] & 0xc0
        if (remoteBits === 0xc0) this.cachedRemoteStartMode = 'OFF'
        else if (remoteBits === 0x80) this.cachedRemoteStartMode = 'PERMANENT'
        else if (remoteBits === 0x40) this.cachedRemoteStartMode = 'ONE_TIME'
        this.publishProperty('remote_start_mode', this.cachedRemoteStartMode)

        // Time display brightness (rsr byte[19] bit 0x40)
        this.cachedBrightness = (rsr[19] & 0x40) !== 0
        this.publishProperty('brightness', this.cachedBrightness ? 'HIGH' : 'LOW')

        // Everything from byte[2] onward (including the State byte itself, for cross-checking)
        // is also published verbatim -- see class header for the fields that remain unmapped.
        this.publishProperty('raw_status_record', rsr.toString('hex').toUpperCase())
    }
}
