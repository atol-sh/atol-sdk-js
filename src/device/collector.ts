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
  type IdentifyResult,
  type SmartSignals,
} from './types'

/** Default Atol API host serving POST /api/v1/devices/identify. */
export const DEFAULT_DEVICE_API_URL = 'https://api.atol.sh'

/**
 * Structural surface of `@atol-sh/fingerprint` consumed here. The package
 * is an OPTIONAL peer dependency, so it cannot be statically imported
 * without breaking installs that skip it. These interfaces mirror the
 * published package API (`AtolFingerprint.load` / `identify`) and the wire
 * shapes are pinned to the server contract -- the fingerprint SDK returns
 * the server JSON verbatim.
 */
interface FingerprintAgent {
  identify(options?: { token?: string }): Promise<IdentifyResult>
}

interface FingerprintStatic {
  load(config?: { endpoint?: string; apiKey?: string }): Promise<FingerprintAgent>
}

interface FingerprintModule {
  AtolFingerprint?: FingerprintStatic
  default?: FingerprintStatic
}

/**
 * Map the server's signals object onto SmartSignals. Only the keys the
 * server actually emits are read -- nothing is fabricated. Returns null
 * when the server sent no signals.
 */
export function parseSignals(raw: unknown): SmartSignals | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  return {
    bot: r.bot === true,
    vpn: r.vpn === true,
    proxy: r.proxy === true,
    tor: r.tor === true,
    incognito: r.incognito === true,
    tampered: r.tampered === true,
    emulator: r.emulator === true,
    rooted: r.rooted === true,
    geo_mismatch: r.geo_mismatch === true,
    anomaly_score: typeof r.anomaly_score === 'number' ? r.anomaly_score : 0,
  }
}

/** Map a raw identify result to the fully-populated DeviceState. */
export function deviceStateFromResult(result: IdentifyResult): DeviceState {
  return {
    deviceId: result.device_id ?? null,
    known: result.known ?? false,
    confidence: result.confidence ?? 0,
    newDevice: result.new_device ?? false,
    platform: result.platform || null,
    browser: result.browser || null,
    osVersion: result.os_version || null,
    signals: parseSignals(result.signals),
    loading: false,
    error: null,
  }
}

/**
 * DeviceCollector loads and caches the fingerprint agent, and performs
 * identify calls. It is stateless with respect to the reactive UI: callers
 * pass an `onState` sink that receives DeviceState transitions, and drive
 * `collect()` in response to token changes / intervals.
 *
 * The agent is (re)loaded when missing or bound to a stale endpoint, so a
 * changed API host does not pin to the first host seen. A single-flight
 * guard keyed by token prevents duplicate concurrent identify POSTs (e.g.
 * React Strict Mode's double invoke).
 */
export class DeviceCollector {
  private agent: FingerprintAgent | null = null
  private agentApiUrl: string | null = null
  private inFlight: Promise<void> | null = null
  private inFlightToken: string | null = null

  constructor(
    private readonly apiUrl: string,
    private readonly onState: (state: DeviceState) => void,
  ) {}

  /**
   * Collect device signals. With a token, submits an identify call and
   * emits the mapped DeviceState; without one, just pre-loads the agent.
   * Concurrent calls with the same token share one in-flight promise.
   */
  collect(token?: string): Promise<void> {
    const key = token ?? null
    if (this.inFlight && this.inFlightToken === key) {
      return this.inFlight
    }

    const run = (async () => {
      this.onState({ ...initialDeviceState, loading: true })
      try {
        let mod: FingerprintModule
        try {
          mod = (await import('@atol-sh/fingerprint')) as FingerprintModule
        } catch (importErr) {
          throw new Error(
            'device intelligence is enabled but @atol-sh/fingerprint is not ' +
              'installed -- run `npm i @atol-sh/fingerprint` or disable device ' +
              `intelligence (${String(importErr)})`,
          )
        }
        const AtolFingerprint = mod.AtolFingerprint ?? mod.default
        if (!AtolFingerprint) {
          throw new Error(
            '@atol-sh/fingerprint loaded but exports no AtolFingerprint -- ' +
              'check the installed package version',
          )
        }

        // (Re)load the agent when missing or bound to a stale endpoint.
        if (!this.agent || this.agentApiUrl !== this.apiUrl) {
          this.agent = await AtolFingerprint.load({ endpoint: this.apiUrl })
          this.agentApiUrl = this.apiUrl
        }

        if (token) {
          const result = await this.agent.identify({ token })
          this.onState(deviceStateFromResult(result))
        } else {
          // No token yet -- agent pre-loaded, nothing to identify.
          this.onState({ ...initialDeviceState, loading: false })
        }
      } catch (err) {
        const error =
          err instanceof Error
            ? err
            : new Error(`Device intelligence collection failed: ${String(err)}`)
        this.onState({ ...initialDeviceState, loading: false, error })
      } finally {
        this.inFlight = null
        this.inFlightToken = null
      }
    })()

    this.inFlight = run
    this.inFlightToken = key
    return run
  }
}
