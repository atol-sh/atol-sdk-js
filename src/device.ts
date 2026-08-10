/**
 * @atol-sh/js/device -- optional device intelligence subpath.
 *
 * Split out from the core barrel so consumers that never use device
 * intelligence do not pull `@atol-sh/fingerprint` (an optional peer
 * dependency, dynamic-imported by the collector) into their bundle.
 */

export {
  DeviceCollector,
  DEFAULT_DEVICE_API_URL,
  deviceStateFromResult,
  parseSignals,
  type DeviceAuthorization,
  type DeviceAuthorizationOwner,
  type DeviceAuthorizationRequest,
  type DeviceCollectionRequest,
} from './device/collector'
export {
  initialDeviceState,
  type DeviceConfig,
  type DeviceState,
  type IdentifyResult,
  type SmartSignals,
} from './device/types'
