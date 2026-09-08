import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import DUT from '@/cloud/devices/H07'
import type { Metadata } from '@/cloud/thinq'
import { MockHAConnection, MockThinq2Device, buf, hex } from '@/tests/helpers/mocks'

const DEVICE_ID = 'test-id'
const MODEL_ID = 'H07'
const META: Metadata = { modelId: MODEL_ID, modelName: MODEL_ID, swVersion: '1.0.0' }

/*
 * Every fixture below is a REAL frame captured on 2026-09-08 from the appliance and from the
 * LG ThinQ app driving it through this bridge. Status frames are `bridge <id> -> ...` (device to
 * cloud); command frames are `bridge <id> <- ...` (cloud to device), i.e. bytes LG itself
 * produced for a given app action. The command tests therefore check our encoder against LG's
 * own output rather than against our reading of it.
 *
 * EC frames carry two 46-byte halves, "before" and "after"; the driver takes the second.
 */

// Upper Express started: state RUNNING, course 8, initial and remaining both 1:46.
const START_UPPER_EXPRESS = buf(
    'aa6232ec001801000001311201013100001c0402014b8664044005000005050d0a00000103ce003e0103ce003e0103ce003e' +
        '0018020200012e0800012e00001c0c02014b8664044000100005050d0a00000103ce003e0103ce003e0103ce003e66bb',
)

// The same job paused: only the state byte moves, 0x02 -> 0x03.
const PAUSED = buf(
    'aa6232ec0018020200012e0800012e00001c0c02014b8664044000100005050d0a00000103ce003e0103ce003e0103ce003e' +
        '0018030200012e0800012e00001c0c02014b8664044000100005050d0a00000103ce003e0103ce003e0103ce003e6cbb',
)

// Cancelled: process 0x63, remaining drops to 0:01, course cleared.
const CANCELLING = buf(
    'aa6232ec0018030200012e0800012e00001c0c02014b8664044000100005050d0a00000103ce003e0103ce003e0103ce003e' +
        '0018026300012e000000010000140002014b8464044000000005050d0a00000103ce003e0103ce003e0103ce003e6bbb',
)

// Idle after the settings run: buzzer OFF, rinse level 1, front time display back ON.
const IDLE_BUZZER_OFF = buf(
    'aa6232ec001801000002081000020800001c000101038664044000000005050d0a00000103ce003e0103ce003e0103ce003e' +
        '001801000002081000020800001c0001010b8664044000000005050d0a00000103ce003e0103ce003e0103ce003eb9bb',
)

// A 3-hour delay start armed: state RUNNING but process RESERVED, reserve time 3:00.
const DELAY_START_ARMED = buf(
    'aa6232ec001801000002081000020800001c0001010b8664044000000005050d0a00000103ce003e0103ce003e0103ce003e' +
        '001802010002081000020803001c0101010b8664044000000005050d0a00000103ce003e0103ce003e0103ce003eafbb',
)

function makeDevice() {
    const HA = new MockHAConnection()
    const thinq = new MockThinq2Device(DEVICE_ID, META)
    const dev = new DUT(HA.asConnection(), thinq, META)
    dev.start()
    thinq.resetRecorder()
    return { HA, thinq, dev }
}

function props(HA: MockHAConnection) {
    return HA.devices[DEVICE_ID].properties
}

describe('H07 status decoding', () => {
    test('a running course reports its course, state and both times', () => {
        const { HA, thinq } = makeDevice()
        thinq.emit('data', START_UPPER_EXPRESS)

        const p = props(HA)
        assert.equal(p.state, 'RUNNING')
        assert.equal(p.process, 'RUNNING')
        assert.equal(p.power, 'ON')
        assert.equal(p.course, 'UPPER_EXPRESS')
        assert.equal(p.course_time, 106) // 1:46
        assert.equal(p.remain_time, 106)
        assert.equal(p.reserve_time, 0)
        assert.equal(p.door, 'CLOSE')
    })

    test('pausing moves the state byte alone', () => {
        const { HA, thinq } = makeDevice()
        thinq.emit('data', START_UPPER_EXPRESS)
        const before = { ...props(HA) }
        thinq.emit('data', PAUSED)
        const after = props(HA)

        assert.equal(after.state, 'PAUSE')
        for (const key of Object.keys(before)) {
            if (key === 'state' || key === 'status_frame_count' || key === 'raw_status_record') continue
            assert.equal(after[key], before[key], `${key} should not change when pausing`)
        }
    })

    test('a cancel is reported as draining, not as powered off', () => {
        const { HA, thinq } = makeDevice()
        thinq.emit('data', CANCELLING)

        const p = props(HA)
        assert.equal(p.process, 'CANCEL')
        assert.equal(p.course, 'NONE') // the course byte is cleared while draining
        assert.equal(p.remain_time, 1) // 0:01, and the unit really does finish a minute later
        assert.equal(p.power, 'ON') // H11 would say OFF here; this unit is still awake
    })

    test('a delay start reads as RESERVED with a counting-down reserve time', () => {
        const { HA, thinq } = makeDevice()
        thinq.emit('data', DELAY_START_ARMED)

        const p = props(HA)
        assert.equal(p.state, 'RUNNING') // the unit says RUNNING even though it is only waiting
        assert.equal(p.process, 'RESERVED')
        assert.equal(p.reserve_time, 180) // 3:00
        assert.equal(p.course, 'OVERNIGHT')
    })

    test('settings come back off the status record', () => {
        const { HA, thinq } = makeDevice()
        thinq.emit('data', IDLE_BUZZER_OFF)

        const p = props(HA)
        assert.equal(p.buzzer_level, 'OFF')
        assert.equal(p.rinse_level, 1)
        assert.equal(p.softening_level, 1)
        assert.equal(p.time_indicator, 'ON')
        assert.equal(p.end_alarm_sound, 'ON')
        assert.equal(p.auto_dry, 'ON')
        assert.equal(p.wash_complete_light, 'OFF')
        assert.equal(p.brightness, 'HIGH')
        assert.equal(p.remote_start_mode, 'PERMANENT')
    })
})

describe('H07 commands reproduce the bytes LG sent', () => {
    // Each expectation is the exact frame captured from the LG cloud for that app action.
    const simple: [string, string, string][] = [
        ['power', 'OFF', 'AA07F026128CBB'],
        ['power', 'ON', 'AA07F0261688BB'],
        ['pause_course', 'PRESS', 'AA07F026138FBB'],
        ['resume_course', 'PRESS', 'AA07F026148EBB'],
        ['cancel_course', 'PRESS', 'AA07F026118DBB'],
    ]

    for (const [prop, value, expected] of simple) {
        test(`${prop}=${value}`, () => {
            const { thinq, dev } = makeDevice()
            dev.setProperty(prop, value)
            assert.equal(thinq.outbox.length, 1)
            assert.equal(hex(thinq.outbox[0]), expected)
        })
    }

    test('starting Overnight three hours out matches the app byte for byte', () => {
        const { thinq, dev } = makeDevice()
        dev.setProperty('target_course', 'OVERNIGHT')
        dev.setProperty('target_delay', '3')
        thinq.resetRecorder()

        dev.setProperty('start_course', 'PRESS')
        assert.equal(hex(thinq.outbox[0]), 'AA0DF02610100300000000A5BB')
    })

    test('starting Upper Express with high temp, extra dry and one extra rinse', () => {
        const { thinq, dev } = makeDevice()
        dev.setProperty('target_course', 'UPPER_EXPRESS')
        dev.setProperty('target_high_temp', 'ON')
        dev.setProperty('target_extra_dry', 'ON')
        dev.setProperty('target_extra_rinse', '1')
        thinq.resetRecorder()

        dev.setProperty('start_course', 'PRESS')
        // opt3 = 0x08|0x04, opt4 = 0x08 -- the option bytes the app itself sent for this course.
        assert.equal(hex(thinq.outbox[0]), 'AA0DF026100800000C0800ACBB')
    })

    test('a settings change resends the whole set', () => {
        const { thinq, dev } = makeDevice()
        // Adopt the appliance's real state first, exactly as a status record would.
        thinq.emit('data', IDLE_BUZZER_OFF)
        thinq.resetRecorder()

        dev.setProperty('buzzer_level', 'LOW')
        // rinse 1, softening 1, opt1 = end alarm|auto dry|time display|buzzer LOW, opt2 = remote
        // start PERMANENT, opt3 = brightness HIGH.
        assert.equal(hex(thinq.outbox[0]), 'AA0EF026010172804000000057BB')
    })

    test('a downloaded course starts by slot, and does not turn steam on by itself', () => {
        const { thinq, dev } = makeDevice()
        dev.setProperty('target_course', 'DOWNLOAD_CYCLE')
        dev.setProperty('target_download_slot', '3')
        dev.setProperty('target_extra_dry', 'ON')
        thinq.resetRecorder()

        dev.setProperty('start_course', 'PRESS')
        // Exactly what the app sent for slot 3 (RINSING at the time), with no delay: opt3 is the
        // extra-dry bit alone and opt4 carries the slot. An earlier revision set opt3 bit 0x80
        // here, which is steam.
        assert.equal(hex(thinq.outbox[0]), 'AA0DF026100B000004400079BB')
    })

    test('writing a course into a slot matches the captured download frame', () => {
        const { thinq, dev } = makeDevice()
        dev.setProperty('target_download_slot', '3')
        dev.setProperty('target_download_course', 'PRESSED_TABLEWARE')
        thinq.resetRecorder()

        dev.setProperty('download_course', 'PRESS')
        assert.equal(hex(thinq.outbox[0]), 'AA15F02503000E0600000440000000000000007ABB')
    })

    test('a course whose options cannot be encoded is refused', () => {
        const { thinq, dev } = makeDevice()
        dev.setProperty('target_download_course', 'DELICATE') // spray-force defaults
        thinq.resetRecorder()

        dev.setProperty('download_course', 'PRESS')
        assert.equal(thinq.outbox.length, 0)
    })

    test('the download slots are read out of the status record', () => {
        const { HA, thinq } = makeDevice()
        thinq.emit('data', IDLE_BUZZER_OFF)

        const p = props(HA)
        assert.equal(p.download_slot_1, 'GREASY_TABLEWARE')
        assert.equal(p.download_slot_2, 'MACHINE_CLEAN')
        assert.equal(p.download_slot_3, 'RINSING')
        assert.equal(p.current_download_course, 'GREASY_TABLEWARE')
    })

    test('an unknown property sends nothing', () => {
        const { thinq, dev } = makeDevice()
        dev.setProperty('not-a-real-property', 'whatever')
        assert.equal(thinq.outbox.length, 0)
    })

    test('staging a course sends nothing until start is pressed', () => {
        const { thinq, dev } = makeDevice()
        dev.setProperty('target_course', 'INTENSIVE')
        dev.setProperty('target_delay', '5')
        dev.setProperty('target_high_temp', 'ON')
        assert.equal(thinq.outbox.length, 0)
    })
})
