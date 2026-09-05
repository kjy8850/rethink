import HADevice from './base'
import { Device as Thinq2Device } from '../thinq2/device'
import { DeviceDiscovery, type Connection } from '../homeassistant'
import { type Metadata } from '../thinq'
import { allowExtendedType } from '@/util/casting'
import AABBDevice from './aabb_device'
import log from '@/util/logging'

/*
 * LG Dishwasher H07 (ThinQ modelName "H07", modelId/kind "H07", DeviceType 204,
 * modemType RTK_RTL8720cm). STUB HANDLER -- field mapping unknown.
 *
 * Status: unregistered as of 2026-09-05. This handler exists only so that the physical
 * unit gets a proper HA device entry with raw diagnostic sensors instead of being
 * dropped with "thinq2 device type H07 unknown" (see ha_bridge.ts). No field has been
 * confirmed against real dishwasher behavior (course selection, running, door, etc.) --
 * everything below was inferred purely from framing structure captured incidentally
 * during a brief, accidental provisioning on 2026-09-05 while the unit was idle right
 * after a power-on reset. Do NOT trust field offsets; only the envelope/framing below
 * is verified.
 *
 * ---- What IS confirmed (from real captured device_packet payloads) ----
 * The wire format is the same "AA [len] ...inner [checksum^0x55] BB" envelope used by
 * H11.ts (see aabb_device.ts) -- confirmed because the observed `len` byte always equals
 * `inner.length + 4` exactly, for three different inner lengths (48, 49, 94 bytes).
 *
 * Inside that envelope, every observed frame starts with 0x32 (matches H11's convention),
 * with a second byte that varies by frame kind. Three second-byte values were observed:
 *   0xEC -- payload is DOUBLED (two identical halves back-to-back), exactly like H11's
 *           STATUS frame (`buf[0]===0x32 && buf[1]===0xec` in H11.ts). We reuse H11's
 *           halfLen-extraction trick for this marker.
 *   0xEB, 0xB2 -- single (non-doubled) payload, purpose unknown. Bodies looked like:
 *           EB: 08 18 00 00 00 01 31 00 00 01 31 00 00 1E 00 02 01 49 44 64 04 C2 00 0A
 *               00 05 05 0D 0A 00 00 01 03 CE 00 3E 01 03 CE 00 3E 01 03 CE 00 3E
 *           B2: 00 08 18 00 00 00 01 31 00 00 01 31 00 00 1E 00 02 01 49 44 64 04 C2 00
 *               0A 00 05 05 0D 0A 00 00 01 03 CE 00 3E 01 03 CE 00 3E 01 03 CE 00 3E
 *           (B2 looks like EB with one extra leading 0x00 -- possibly a sequence/flags
 *           byte prepended, or EB/B2 are unrelated frame kinds that happen to share a
 *           tail. Unconfirmed.)
 * All three captures happened moments after a POWER_ON reset with the door presumably
 * closed and no cycle running, so these bytes most likely represent an IDLE/STANDBY
 * state snapshot, not a meaningful spread of field values. They are NOT enough to map
 * course/state/door/timer offsets (unlike H11, where those were reverse-engineered
 * against real running cycles).
 *
 * ---- What to do next (see session report for the full plan) ----
 * 1. Re-provision the physical unit onto rethink for real (AP-mode reset, per the
 *    session report's manual steps).
 * 2. Run real cycles (start, pause, door open/close, cycle-end) while this handler is
 *    active -- every raw frame gets published to `$this/raw_frame` / `$this/frame_kind`,
 *    and is also visible unfiltered in the addon's own "incoming" log line for
 *    `clip/message/devices/<id>` with `cmd":"device_packet"`.
 * 3. Correlate frame_kind + raw_frame changes against what the dishwasher's own front
 *    panel / LG app shows at that moment, to pin down byte offsets for state, course,
 *    remaining time, door, options, etc. -- same method used for H11.ts's DISHWASHER_STATES/
 *    COURSES/RINSE_LEVELS tables and processStatus() offsets.
 * 4. Only after that mapping exists, replace the raw sensors below with real typed
 *    components (select/binary_sensor/number/button) mirroring H11.ts's component set,
 *    and implement setProperty()/send() for actual commands. Until real command bytes
 *    are confirmed, do NOT guess at write commands -- an incorrect command sent to a
 *    dishwasher (unlike a read) can trigger an unwanted physical action.
 */
export default class Device extends AABBDevice {
    readonly deviceConfig: DeviceDiscovery

    constructor(HA: Connection, thinq: Thinq2Device, meta: Metadata) {
        super(HA, thinq)
        this.deviceConfig = HADevice.config(meta, { name: 'LG Dishwasher (H07, unmapped)' })

        this.setConfig(
            allowExtendedType({
                ...this.deviceConfig,
                components: {
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
                        name: 'Raw Frame Hex (diagnostic)',
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
                },
            }),
        )
    }

    private frameCount = 0

    setProperty(prop: string, mqttValue: string) {
        // No confirmed writable field yet -- see the TODO block above the class.
        console.warn(`H07 (stub): attempted to set '${prop}'='${mqttValue}', but no commands are implemented yet`)
    }

    processAABB(buf: Buffer) {
        // buf here is already stripped of the outer AA/len .. checksum/BB (see aabb_device.ts)
        if (buf.length < 2 || buf[0] !== 0x32) {
            log('status', this.id, 'H07 (stub): unrecognized frame, first byte', buf[0]?.toString(16))
            return
        }

        const marker = buf[1]
        let payload: Buffer

        if (marker === 0xec) {
            // Same "doubled payload" shape as H11's status frame -- take the second half.
            const payloadLen = buf.length - 2
            const halfLen = Math.floor(payloadLen / 2)
            payload = halfLen > 0 ? buf.subarray(2 + halfLen, buf.length) : buf.subarray(2)
        } else {
            payload = buf.subarray(2)
        }

        this.frameCount += 1
        this.publishProperty('frame_kind', '0x' + marker.toString(16).padStart(2, '0'))
        this.publishProperty('raw_frame', payload.toString('hex').toUpperCase())
        this.publishProperty('raw_frame_count', this.frameCount)

        log('status', this.id, 'H07 (stub): frame kind', marker.toString(16), 'payload', payload.toString('hex'))
    }
}
