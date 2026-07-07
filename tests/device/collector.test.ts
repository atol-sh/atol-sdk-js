/**
 * DeviceCollector contract tests.
 *
 * The fixture below is the EXACT shape the server returns from
 * POST /api/v1/devices/identify: snake_case top-level fields and the ten
 * smart-signal keys. The collector must map those real fields and must not
 * fabricate any signal the server does not send.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  DeviceCollector,
  deviceStateFromResult,
  parseSignals,
} from '../../src/device/collector'
import type { DeviceState } from '../../src/device/types'
import { loadMock } from '../stubs/fingerprint'

const serverFixture = {
  device_id: 'dev_01HXYZ',
  known: true,
  confidence: 0.92,
  new_device: false,
  platform: 'macOS',
  browser: 'Chrome',
  os_version: '15.5',
  signals: {
    bot: false,
    vpn: true,
    proxy: false,
    tor: false,
    incognito: true,
    tampered: false,
    emulator: false,
    rooted: false,
    geo_mismatch: true,
    anomaly_score: 0.35,
  },
}

let identifyMock: ReturnType<typeof vi.fn>

/** Drive the collector and capture the last emitted state. */
async function runCollect(
  apiUrl: string,
  token: string | undefined,
): Promise<{ states: DeviceState[]; last: DeviceState }> {
  const states: DeviceState[] = []
  const collector = new DeviceCollector(apiUrl, (s) => states.push(s))
  await collector.collect(token)
  return { states, last: states[states.length - 1] }
}

beforeEach(() => {
  identifyMock = vi.fn().mockResolvedValue(serverFixture)
  loadMock.mockReset()
  loadMock.mockResolvedValue({ identify: identifyMock })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('parseSignals', () => {
  it('maps exactly the ten server keys with no fabrication', () => {
    const s = parseSignals(serverFixture.signals)
    expect(s).toEqual(serverFixture.signals)
    expect(Object.keys(s!).sort()).toEqual(
      [
        'anomaly_score',
        'bot',
        'emulator',
        'geo_mismatch',
        'incognito',
        'proxy',
        'rooted',
        'tampered',
        'tor',
        'vpn',
      ].sort(),
    )
  })

  it('returns null for a null / non-object payload', () => {
    expect(parseSignals(null)).toBeNull()
    expect(parseSignals(undefined)).toBeNull()
    expect(parseSignals('nope')).toBeNull()
  })

  it('coerces missing booleans to false and non-number anomaly_score to 0', () => {
    const s = parseSignals({ bot: 'truthy', anomaly_score: 'high' })
    expect(s!.bot).toBe(false)
    expect(s!.anomaly_score).toBe(0)
  })
})

describe('deviceStateFromResult', () => {
  it('maps the server identify response field-for-field', () => {
    expect(deviceStateFromResult(serverFixture)).toEqual({
      deviceId: 'dev_01HXYZ',
      known: true,
      confidence: 0.92,
      newDevice: false,
      platform: 'macOS',
      browser: 'Chrome',
      osVersion: '15.5',
      signals: serverFixture.signals,
      loading: false,
      error: null,
    })
  })
})

describe('DeviceCollector.collect', () => {
  it('loads the agent against the API host and identifies with the token', async () => {
    const { last } = await runCollect('https://api.atol.sh', 'at_token')
    expect(loadMock).toHaveBeenCalledWith({ endpoint: 'https://api.atol.sh' })
    expect(identifyMock).toHaveBeenCalledWith({ token: 'at_token' })
    expect(last.deviceId).toBe('dev_01HXYZ')
    expect(last.signals).toEqual(serverFixture.signals)
  })

  it('honors an explicit apiUrl endpoint', async () => {
    await runCollect('https://api.eu-1.atol.sh', 'at_token')
    expect(loadMock).toHaveBeenCalledWith({ endpoint: 'https://api.eu-1.atol.sh' })
  })

  it('pre-loads the agent but does not identify without a token', async () => {
    const { last } = await runCollect('https://api.atol.sh', undefined)
    expect(loadMock).toHaveBeenCalled()
    expect(identifyMock).not.toHaveBeenCalled()
    expect(last.deviceId).toBeNull()
    expect(last.loading).toBe(false)
  })

  it('handles a null signals payload without fabricating signals', async () => {
    identifyMock.mockResolvedValue({ ...serverFixture, signals: null })
    const { last } = await runCollect('https://api.atol.sh', 'at_token')
    expect(last.signals).toBeNull()
  })

  it('surfaces identify failures as error state', async () => {
    identifyMock.mockRejectedValue(new Error('identify request failed: 500'))
    const { last } = await runCollect('https://api.atol.sh', 'at_token')
    expect(last.error).toBeInstanceOf(Error)
    expect(last.deviceId).toBeNull()
    expect(last.loading).toBe(false)
  })

  it('single-flights concurrent identify calls for the same token', async () => {
    let resolveIdentify: ((v: unknown) => void) | undefined
    identifyMock.mockImplementation(
      () => new Promise((res) => (resolveIdentify = res)),
    )
    const collector = new DeviceCollector('https://api.atol.sh', () => {})
    // Both start the same run; the async body (dynamic import -> load ->
    // identify) is in flight. The single-flight guard hands back the same
    // promise synchronously.
    const a = collector.collect('at')
    const b = collector.collect('at')
    expect(a).toBe(b)
    // identify() is reached only after the dynamic import + load resolve, so
    // poll until the mock installs the resolver before completing it.
    await vi.waitFor(() => expect(resolveIdentify).toBeDefined())
    resolveIdentify!(serverFixture)
    await a
    expect(identifyMock).toHaveBeenCalledTimes(1)
  })
})
