/**
 * Framework-agnostic device intelligence collector.
 *
 * Owns the `@atol-sh/fingerprint` agent lifecycle and the identify call,
 * plus the mapping from the server's snake_case response to the
 * binding-facing DeviceState. React (and any other) bindings wrap this
 * with their own reactive state; the collector itself has no framework
 * dependency.
 *
 * This module lives under the optional `@atol-sh/js/device` subpath so a
 * consumer that never uses device intelligence never pulls
 * `@atol-sh/fingerprint` (an optional peer dependency, dynamic-imported
 * here) into their bundle.
 */

import {
  initialDeviceState,
  type DeviceState,
  type SmartSignals,
} from './types'

/** Default Atol API host serving POST /api/v1/devices/identify. */
export const DEFAULT_DEVICE_API_URL = 'https://api.atol.sh'

/**
 * Structural surface of `@atol-sh/fingerprint` consumed here. The package
 * is an OPTIONAL peer dependency, so it cannot be statically imported
 * without breaking installs that skip it. These interfaces mirror the
 * published package API (`AtolFingerprint.load` / `identify`) and the wire
 * shapes are pinned to the server contract. This boundary validates the
 * dynamically loaded package result independently before exposing state.
 */
interface FingerprintAgent {
  identify(options?: { authorize?: DeviceAuthorizationOwner }): Promise<unknown>
}

interface FingerprintStatic {
  load(config?: { endpoint?: string }): Promise<FingerprintAgent>
}

interface FingerprintModule {
  AtolFingerprint?: FingerprintStatic
  default?: FingerprintStatic
}

/** Exact identify request presented to the credential owner. */
export interface DeviceAuthorizationRequest {
  method: 'POST'
  url: string
}

/** One request's exact Bearer or DPoP authorization material. */
export type DeviceAuthorization =
  | {
      scheme: 'Bearer'
      accessToken: string
    }
  | {
      scheme: 'DPoP'
      accessToken: string
      dpopProof: string
    }

/**
 * Acquire authorization for the exact identify request. The collector passes
 * this owner through for one operation and does not retain its result.
 */
export type DeviceAuthorizationOwner = (
  request: Readonly<DeviceAuthorizationRequest>,
) => Promise<DeviceAuthorization>

/**
 * One credential generation's identify authority. Increment the non-secret
 * generation whenever the owning session rotates or changes organization.
 */
export interface DeviceCollectionRequest {
  credentialGeneration: number
  authorize: DeviceAuthorizationOwner
}

type DeviceDiagnosticCode =
  | 'device_dependency_unavailable'
  | 'device_dependency_invalid'
  | 'device_initialization_failed'
  | 'device_collection_failed'
  | 'device_credential_generation_invalid'
  | 'device_response_invalid'

class DeviceDiagnosticError extends Error {
  readonly code: DeviceDiagnosticCode

  constructor(code: DeviceDiagnosticCode, message: string) {
    super(message)
    this.code = code
    this.name = 'DeviceDiagnosticError'
  }
}

/**
 * Map the exact server signals object onto SmartSignals. Missing, null,
 * unknown, or mistyped members are a contract failure.
 */
export function parseSignals(raw: unknown): SmartSignals {
  const expectedKeys = [
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
  ]
  if (!isExactRecord(raw, expectedKeys)) {
    throw invalidDeviceResponse()
  }
  const r = raw as Record<string, unknown>
  if (
    typeof r.bot !== 'boolean' ||
    typeof r.vpn !== 'boolean' ||
    typeof r.proxy !== 'boolean' ||
    typeof r.tor !== 'boolean' ||
    typeof r.incognito !== 'boolean' ||
    typeof r.tampered !== 'boolean' ||
    typeof r.emulator !== 'boolean' ||
    typeof r.rooted !== 'boolean' ||
    typeof r.geo_mismatch !== 'boolean' ||
    typeof r.device_mismatch !== 'boolean' ||
    typeof r.device_shared !== 'boolean' ||
    typeof r.shared_user_count !== 'number' ||
    !Number.isSafeInteger(r.shared_user_count) ||
    r.shared_user_count < 0 ||
    !isProbability(r.anomaly_score)
  ) {
    throw invalidDeviceResponse()
  }
  return {
    bot: r.bot,
    vpn: r.vpn,
    proxy: r.proxy,
    tor: r.tor,
    incognito: r.incognito,
    tampered: r.tampered,
    emulator: r.emulator,
    rooted: r.rooted,
    geo_mismatch: r.geo_mismatch,
    device_mismatch: r.device_mismatch,
    device_shared: r.device_shared,
    shared_user_count: r.shared_user_count,
    anomaly_score: r.anomaly_score,
  }
}

function isExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const actualKeys = Object.keys(value).sort()
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index])
  )
}

function isProbability(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  )
}

function invalidDeviceResponse(): DeviceDiagnosticError {
  return new DeviceDiagnosticError(
    'device_response_invalid',
    'Device intelligence returned an invalid response.',
  )
}

/** Validate and map a raw identify result to the fully-populated DeviceState. */
export function deviceStateFromResult(result: unknown): DeviceState {
  const expectedKeys = [
    'browser',
    'confidence',
    'device_id',
    'known',
    'new_device',
    'os_version',
    'platform',
    'signals',
  ]
  if (!isExactRecord(result, expectedKeys)) {
    throw invalidDeviceResponse()
  }
  if (
    typeof result.device_id !== 'string' ||
    result.device_id.length === 0 ||
    typeof result.known !== 'boolean' ||
    typeof result.new_device !== 'boolean' ||
    result.known === result.new_device ||
    !isProbability(result.confidence) ||
    typeof result.platform !== 'string' ||
    typeof result.browser !== 'string' ||
    typeof result.os_version !== 'string'
  ) {
    throw invalidDeviceResponse()
  }
  return {
    deviceId: result.device_id,
    known: result.known,
    confidence: result.confidence,
    newDevice: result.new_device,
    platform: result.platform,
    browser: result.browser,
    osVersion: result.os_version,
    signals: parseSignals(result.signals),
    loading: false,
    error: null,
  }
}

/**
 * DeviceCollector loads and caches the fingerprint agent, and performs
 * identify calls. It is stateless with respect to the reactive UI: callers
 * pass an `onState` sink that receives DeviceState transitions, and drive
 * `collect()` in response to credential-generation changes or intervals.
 *
 * The agent is loaded once for this endpoint-bound collector. Calls for one
 * credential generation are single-flight. A newer generation becomes the
 * latest intent immediately, so a late older result cannot publish state.
 */
export class DeviceCollector {
  private agent: FingerprintAgent | null = null
  private agentLoad: Promise<FingerprintAgent> | null = null
  private readonly inFlight = new Map<number, Promise<void>>()
  private highestCredentialGeneration = 0
  private invalidatedGenerationFloor = 0
  private latestIntent = 0

  constructor(
    private readonly apiUrl: string,
    private readonly onState: (state: DeviceState) => void,
  ) {}

  /**
   * Pre-load the fingerprint agent without changing credential authority.
   * A later collect or invalidate operation fences this preparation's state.
   */
  async prepare(): Promise<void> {
    const intent = this.latestIntent
    try {
      await this.loadAgent()
      this.publishPreparation(intent, {
        ...initialDeviceState,
        loading: false,
      })
    } catch (err) {
      const error =
        err instanceof DeviceDiagnosticError
          ? err
          : new DeviceDiagnosticError(
              'device_collection_failed',
              'Device intelligence collection failed. Retry the request.',
            )
      this.publishPreparation(intent, {
        ...initialDeviceState,
        loading: false,
        error,
      })
    }
  }

  /**
   * Submit one credential generation's identify operation. Generations are
   * strictly monotonic for this collector's lifetime. A lower delayed
   * generation is ignored before authorization or network dispatch, while a
  * newer generation immediately fences every older result.
  */
  collect(request: DeviceCollectionRequest): Promise<void> {
    const {
      credentialGeneration: generation,
      authorize,
    } = request
    if (!Number.isSafeInteger(generation) || generation <= 0) {
      return Promise.reject(
        new DeviceDiagnosticError(
          'device_credential_generation_invalid',
          'Device intelligence requires a positive credential generation.',
        ),
      )
    }
    if (
      generation < this.highestCredentialGeneration ||
      generation <= this.invalidatedGenerationFloor
    ) {
      return Promise.resolve()
    }
    const existing = this.inFlight.get(generation)
    if (existing) {
      return existing
    }
    if (generation > this.highestCredentialGeneration) {
      this.highestCredentialGeneration = generation
    }
    const intent = ++this.latestIntent

    const operation = (async () => {
      this.publish(intent, { ...initialDeviceState, loading: true })
      try {
        const agent = await this.loadAgent()
        let result: unknown
        try {
          result = await agent.identify({ authorize })
        } catch {
          throw new DeviceDiagnosticError(
            'device_collection_failed',
            'Device intelligence collection failed. Retry the request.',
          )
        }
        this.publish(intent, deviceStateFromResult(result))
      } catch (err) {
        const error =
          err instanceof DeviceDiagnosticError
            ? err
            : new DeviceDiagnosticError(
                'device_collection_failed',
                'Device intelligence collection failed. Retry the request.',
              )
        this.publish(intent, { ...initialDeviceState, loading: false, error })
      }
    })()

    let run: Promise<void>
    run = operation.finally(() => {
      if (this.inFlight.get(generation) === run) {
        this.inFlight.delete(generation)
      }
    })
    this.inFlight.set(generation, run)
    return run
  }

  /**
   * Fence every in-flight identify and clear published device state. Future
   * credentials must continue with a generation higher than any accepted one.
   */
  invalidate(): void {
    this.latestIntent++
    this.invalidatedGenerationFloor = Math.max(
      this.invalidatedGenerationFloor,
      this.highestCredentialGeneration,
    )
    this.onState(initialDeviceState)
  }

  private publishPreparation(intent: number, state: DeviceState): void {
    if (this.highestCredentialGeneration === 0) {
      this.publish(intent, state)
    }
  }

  private publish(intent: number, state: DeviceState): void {
    if (intent === this.latestIntent) {
      this.onState(state)
    }
  }

  private async loadAgent(): Promise<FingerprintAgent> {
    if (this.agent) {
      return this.agent
    }
    if (this.agentLoad) {
      return this.agentLoad
    }

    const load = (async () => {
      let mod: FingerprintModule
      try {
        mod = (await import('@atol-sh/fingerprint')) as FingerprintModule
      } catch {
        throw new DeviceDiagnosticError(
          'device_dependency_unavailable',
          'device intelligence is enabled but @atol-sh/fingerprint is not ' +
            'installed -- run `npm i @atol-sh/fingerprint` or disable device ' +
            'intelligence',
        )
      }
      const AtolFingerprint = mod.AtolFingerprint ?? mod.default
      if (!AtolFingerprint) {
        throw new DeviceDiagnosticError(
          'device_dependency_invalid',
          '@atol-sh/fingerprint loaded but exports no AtolFingerprint -- ' +
            'check the installed package version',
        )
      }

      try {
        const agent = await AtolFingerprint.load({ endpoint: this.apiUrl })
        this.agent = agent
        return agent
      } catch {
        throw new DeviceDiagnosticError(
          'device_initialization_failed',
          'Device intelligence could not be initialized. Retry or disable device intelligence.',
        )
      }
    })()

    this.agentLoad = load
    try {
      return await load
    } finally {
      if (this.agentLoad === load) {
        this.agentLoad = null
      }
    }
  }
}
