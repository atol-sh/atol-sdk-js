/**
 * DeviceCollector contract tests.
 *
 * The fixture below is the EXACT shape the server returns from
 * POST /api/v1/devices/identify: snake_case top-level fields and thirteen
 * smart-signal keys. The collector must map those real fields and must not
 * fabricate any signal the server does not send.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  DeviceCollector,
  deviceStateFromResult,
  parseSignals,
  type DeviceAuthorizationOwner,
} from '../../src/device/collector'
import {
  initialDeviceState,
  type DeviceState,
} from '../../src/device/types'
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
    device_mismatch: false,
    device_shared: true,
    shared_user_count: 2,
    anomaly_score: 0.35,
  },
}

let identifyMock: ReturnType<typeof vi.fn>

/** Drive the collector and capture the last emitted state. */
async function runCollect(
  apiUrl: string,
  credentialGeneration: number | null,
): Promise<{ states: DeviceState[]; last: DeviceState }> {
  const states: DeviceState[] = []
  const collector = new DeviceCollector(apiUrl, (s) => states.push(s))
  if (credentialGeneration === null) {
    await collector.prepare()
  } else {
    await collector.collect({
      credentialGeneration,
      authorize: bearerOwner(),
    })
  }
  return { states, last: states[states.length - 1] }
}

function bearerOwner(
  accessToken = 'at_token',
): DeviceAuthorizationOwner {
  return async () => ({ scheme: 'Bearer', accessToken })
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
  it('maps exactly the thirteen server keys with no fabrication', () => {
    const s = parseSignals(serverFixture.signals)
    expect(s).toEqual(serverFixture.signals)
    expect(Object.keys(s!).sort()).toEqual(
      [
        'anomaly_score',
        'bot',
        'device_mismatch',
        'device_shared',
        'emulator',
        'geo_mismatch',
        'incognito',
        'proxy',
        'rooted',
        'shared_user_count',
        'tampered',
        'tor',
        'vpn',
      ].sort(),
    )
  })

  it('rejects null and every other non-object signal value', () => {
    expect(() => parseSignals(null)).toThrow(
      'Device intelligence returned an invalid response.',
    )
    expect(() => parseSignals(undefined)).toThrow(
      'Device intelligence returned an invalid response.',
    )
    expect(() => parseSignals('nope')).toThrow(
      'Device intelligence returned an invalid response.',
    )
  })

  it('rejects missing or mistyped smart signals without fabricating defaults', () => {
    expect(() =>
      parseSignals({ bot: 'truthy', anomaly_score: 'high' }),
    ).toThrow('Device intelligence returned an invalid response.')
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
  it('loads the agent and delegates exact authorization to its owner', async () => {
    const authorize = bearerOwner()
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )
    await collector.collect({ credentialGeneration: 1, authorize })
    const last = states[states.length - 1]
    expect(loadMock).toHaveBeenCalledWith({ endpoint: 'https://api.atol.sh' })
    expect(identifyMock).toHaveBeenCalledWith({ authorize })
    expect(last.deviceId).toBe('dev_01HXYZ')
    expect(last.signals).toEqual(serverFixture.signals)
  })

  it('snapshots the authorization owner before asynchronous loading', async () => {
    let resolveLoad:
      | ((agent: { identify: typeof identifyMock }) => void)
      | undefined
    loadMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveLoad = resolve
        }),
    )
    const originalOwner = bearerOwner('original_token')
    const replacementOwner = vi.fn(bearerOwner('replacement_token'))
    const request = {
      credentialGeneration: 1,
      authorize: originalOwner,
      retainedSecret: 'sentinel-secret-extra-request-member',
    }
    const collector = new DeviceCollector('https://api.atol.sh', () => {})

    const collection = collector.collect(request)
    request.authorize = replacementOwner
    await vi.waitFor(() => expect(resolveLoad).toBeDefined())
    resolveLoad!({ identify: identifyMock })
    await collection

    expect(identifyMock).toHaveBeenCalledWith({ authorize: originalOwner })
    expect(replacementOwner).not.toHaveBeenCalled()
  })

  it('honors an explicit apiUrl endpoint', async () => {
    await runCollect('https://api.eu-1.atol.sh', 1)
    expect(loadMock).toHaveBeenCalledWith({ endpoint: 'https://api.eu-1.atol.sh' })
  })

  it('pre-loads the agent but does not identify without credential authority', async () => {
    const { last } = await runCollect('https://api.atol.sh', null)
    expect(loadMock).toHaveBeenCalled()
    expect(identifyMock).not.toHaveBeenCalled()
    expect(last.deviceId).toBeNull()
    expect(last.loading).toBe(false)
  })

  it('rejects a null signals payload instead of treating it as clean', async () => {
    identifyMock.mockResolvedValue({ ...serverFixture, signals: null })
    const { last } = await runCollect('https://api.atol.sh', 1)
    expect(last.error).toMatchObject({
      code: 'device_response_invalid',
    })
    expect(last.signals).toBeNull()
  })

  it('projects a malformed success payload to a closed failure', async () => {
    const sentinel = 'sentinel-secret-success-member'
    identifyMock.mockResolvedValue({
      ...serverFixture,
      confidence: 'high',
      diagnostic: sentinel,
    })

    const { last } = await runCollect('https://api.atol.sh', 1)

    expect(last.error).toMatchObject({
      name: 'DeviceDiagnosticError',
      code: 'device_response_invalid',
      message: 'Device intelligence returned an invalid response.',
    })
    expect(JSON.stringify(last.error)).not.toContain(sentinel)
    expect(String(last.error)).not.toContain(sentinel)
    expect(last.deviceId).toBeNull()
  })

  it('surfaces a stable identify failure without retaining the caught value', async () => {
    const sentinel = 'sentinel-secret-device-response'
    identifyMock.mockRejectedValue(new Error(sentinel))
    const { last } = await runCollect('https://api.atol.sh', 1)
    expect(last.error).toBeInstanceOf(Error)
    expect(last.error).toMatchObject({
      name: 'DeviceDiagnosticError',
      code: 'device_collection_failed',
      message: 'Device intelligence collection failed. Retry the request.',
    })
    expect(last.error).not.toHaveProperty('cause')
    if (!(last.error instanceof Error)) {
      throw new Error('expected an Error')
    }
    expect(
      [
        last.error.message,
        last.error.stack ?? '',
        JSON.stringify(last.error),
      ].join('\n'),
    ).not.toContain(sentinel)
    expect(last.deviceId).toBeNull()
    expect(last.loading).toBe(false)
  })

  it('single-flights concurrent identify calls for the same owner', async () => {
    let resolveIdentify: ((v: unknown) => void) | undefined
    identifyMock.mockImplementation(
      () => new Promise((res) => (resolveIdentify = res)),
    )
    const collector = new DeviceCollector('https://api.atol.sh', () => {})
    // Both start the same run; the async body (dynamic import -> load ->
    // identify) is in flight. The single-flight guard hands back the same
    // promise synchronously.
    const authorize = bearerOwner()
    const a = collector.collect({
      credentialGeneration: 1,
      authorize,
    })
    const b = collector.collect({
      credentialGeneration: 1,
      authorize: bearerOwner('different_callback_same_generation'),
    })
    expect(a).toBe(b)
    // identify() is reached only after the dynamic import + load resolve, so
    // poll until the mock installs the resolver before completing it.
    await vi.waitFor(() => expect(resolveIdentify).toBeDefined())
    resolveIdentify!(serverFixture)
    await a
    expect(identifyMock).toHaveBeenCalledTimes(1)
  })

  it('suppresses a late result after a newer credential generation starts', async () => {
    let resolveFirst: ((v: unknown) => void) | undefined
    const secondFixture = {
      ...serverFixture,
      device_id: 'dev_new_generation',
    }
    identifyMock
      .mockImplementationOnce(
        () => new Promise((resolve) => (resolveFirst = resolve)),
      )
      .mockResolvedValueOnce(secondFixture)
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )
    const firstOwner = bearerOwner('first_token')
    const secondOwner = bearerOwner('second_token')

    const first = collector.collect({
      credentialGeneration: 1,
      authorize: firstOwner,
    })
    await vi.waitFor(() => expect(resolveFirst).toBeDefined())
    const second = collector.collect({
      credentialGeneration: 2,
      authorize: secondOwner,
    })
    await vi.waitFor(() =>
      expect(states.at(-1)?.deviceId).toBe('dev_new_generation'),
    )
    resolveFirst!(serverFixture)
    await Promise.all([first, second])

    expect(identifyMock).toHaveBeenNthCalledWith(1, {
      authorize: firstOwner,
    })
    expect(identifyMock).toHaveBeenNthCalledWith(2, {
      authorize: secondOwner,
    })
    expect(states.at(-1)?.deviceId).toBe('dev_new_generation')
    expect(states).not.toContainEqual(
      expect.objectContaining({ deviceId: 'dev_01HXYZ' }),
    )
  })

  it('rejects an invalid credential generation before loading the agent', async () => {
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )
    const result = collector.collect({
      credentialGeneration: Number.NaN,
      authorize: bearerOwner(),
    })

    await expect(result).rejects.toMatchObject({
      code: 'device_credential_generation_invalid',
    })
    expect(states).toHaveLength(0)
    expect(loadMock).not.toHaveBeenCalled()
    expect(identifyMock).not.toHaveBeenCalled()
  })

  it('never lets a delayed lower generation regain authority', async () => {
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )
    await collector.collect({
      credentialGeneration: 2,
      authorize: bearerOwner('generation_two'),
    })
    identifyMock.mockClear()

    await collector.collect({
      credentialGeneration: 1,
      authorize: bearerOwner('delayed_generation_one'),
    })

    expect(identifyMock).not.toHaveBeenCalled()
    expect(states.at(-1)?.deviceId).toBe('dev_01HXYZ')
  })

  it('keeps generation two authoritative when generation one is still active', async () => {
    let resolveGenerationOne: ((value: unknown) => void) | undefined
    identifyMock
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveGenerationOne = resolve
          }),
      )
      .mockResolvedValueOnce({
        ...serverFixture,
        device_id: 'generation-two-device',
      })
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )
    const generationOne = collector.collect({
      credentialGeneration: 1,
      authorize: bearerOwner('generation_one'),
    })
    await vi.waitFor(() => expect(resolveGenerationOne).toBeDefined())
    await collector.collect({
      credentialGeneration: 2,
      authorize: bearerOwner('generation_two'),
    })

    const delayedGenerationOne = collector.collect({
      credentialGeneration: 1,
      authorize: bearerOwner('delayed_generation_one'),
    })
    resolveGenerationOne!(serverFixture)
    await Promise.all([generationOne, delayedGenerationOne])

    expect(states.at(-1)?.deviceId).toBe('generation-two-device')
    expect(identifyMock).toHaveBeenCalledTimes(2)
  })

  it('invalidation fences pending preparation and identify state', async () => {
    let resolveIdentify: ((value: unknown) => void) | undefined
    identifyMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveIdentify = resolve
        }),
    )
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )

    const preparation = collector.prepare()
    const identify = collector.collect({
      credentialGeneration: 1,
      authorize: bearerOwner(),
    })
    await vi.waitFor(() => expect(resolveIdentify).toBeDefined())
    collector.invalidate()
    resolveIdentify!(serverFixture)
    await Promise.all([preparation, identify])

    expect(states.at(-1)).toEqual(initialDeviceState)
    expect(states).not.toContainEqual(
      expect.objectContaining({ deviceId: 'dev_01HXYZ' }),
    )
  })

  it('never accepts an invalidated credential generation again', async () => {
    const authorize = vi.fn(bearerOwner('generation_one'))
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )

    await collector.collect({
      credentialGeneration: 1,
      authorize,
    })
    collector.invalidate()
    identifyMock.mockClear()
    authorize.mockClear()

    await collector.collect({
      credentialGeneration: 1,
      authorize,
    })

    expect(authorize).not.toHaveBeenCalled()
    expect(identifyMock).not.toHaveBeenCalled()
    expect(states.at(-1)).toEqual(initialDeviceState)
  })

  it('preparation cannot replace state owned by an accepted generation', async () => {
    const states: DeviceState[] = []
    const collector = new DeviceCollector(
      'https://api.atol.sh',
      (state) => states.push(state),
    )

    await collector.collect({
      credentialGeneration: 1,
      authorize: bearerOwner(),
    })
    const stateCount = states.length
    await collector.prepare()

    expect(states).toHaveLength(stateCount)
    expect(states.at(-1)?.deviceId).toBe('dev_01HXYZ')
    expect(loadMock).toHaveBeenCalledTimes(1)
  })
})
