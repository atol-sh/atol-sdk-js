/**
 * Device intelligence types.
 *
 * Wire shapes mirror the Atol control plane's identify endpoint
 * (`POST /api/v1/devices/identify`) -- the same shapes
 * `@atol-sh/fingerprint` returns from `identify()`. Both packages validate
 * the response before exposing it. The fingerprint package
 * is an optional peer dependency that is not statically resolvable
 * here, so the contract is mirrored locally instead of imported.
 */

/** Configuration for device intelligence collection. */
export interface DeviceConfig {
  /** Whether device intelligence is enabled. */
  enabled: boolean

  /**
   * Base URL of the Atol API host that serves
   * `POST /api/v1/devices/identify`. This is the API host
   * (https://api.atol.sh), NOT the OIDC authority (https://auth.atol.sh).
   * Default: "https://api.atol.sh".
   */
  apiUrl?: string

  /** Collect device signals on mount. Default: true. */
  collectOnMount?: boolean

  /** Interval in ms to re-collect signals. 0 = disabled. Default: 0. */
  recheckInterval?: number
}

/**
 * Smart signals computed server-side. Keys match the server's signals
 * map exactly (snake_case); no client-side fabrication.
 */
export interface SmartSignals {
  bot: boolean
  vpn: boolean
  proxy: boolean
  tor: boolean
  incognito: boolean
  tampered: boolean
  emulator: boolean
  rooted: boolean
  geo_mismatch: boolean
  device_mismatch: boolean
  device_shared: boolean
  shared_user_count: number
  anomaly_score: number
}

/**
 * Raw identify response from the control plane (snake_case, verbatim).
 * The server always returns the exact smart-signal evaluation.
 */
export interface IdentifyResult {
  device_id: string
  known: boolean
  confidence: number
  new_device: boolean
  platform: string
  browser: string
  os_version: string
  signals: SmartSignals
}

/** Device intelligence state (binding-facing, camelCase). */
export interface DeviceState {
  /** Unique device identifier assigned by the Atol control plane. */
  deviceId: string | null

  /** Whether this device has been seen before. */
  known: boolean

  /** Confidence score (0-1) for the device fingerprint match. */
  confidence: number

  /** Whether the server created a new device record for this identify. */
  newDevice: boolean

  /** Platform reported by the server (e.g. "macOS"). Null before identify. */
  platform: string | null

  /** Browser family reported by the server. Null before identify. */
  browser: string | null

  /** OS version reported by the server. Null before identify. */
  osVersion: string | null

  /** Smart signals from server-side analysis. Null before identify, reset,
   * or failure; every successful server response contains the exact object. */
  signals: SmartSignals | null

  /** Whether device intelligence is currently loading. */
  loading: boolean

  /** Error from device intelligence collection, if any. */
  error: Error | null
}

/** Initial / not-collected device state. Shared by bindings' context
 * default and the no-provider fallback. */
export const initialDeviceState: DeviceState = {
  deviceId: null,
  known: false,
  confidence: 0,
  newDevice: false,
  platform: null,
  browser: null,
  osVersion: null,
  signals: null,
  loading: false,
  error: null,
}
