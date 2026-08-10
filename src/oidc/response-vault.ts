/**
 * Public browser authorization response-vault v1 facade.
 *
 * The implementation is layered behind an explicit internal context so
 * authorization material stays out of navigation URLs and cross-window
 * messages without coupling internal domains back to this public entrypoint.
 */

import type { ResponseVaultConfig } from './response-vault-contract'
import { ResponseVaultNavigation } from './response-vault-navigation'

export {
  RESPONSE_VAULT_PROTOCOL_VERSION,
  ResponseVaultAuthorizationBindingMismatchError,
  ResponseVaultAuthorizationInvalidatedError,
  ResponseVaultCleanupPendingError,
  ResponseVaultDeliveryUnavailableError,
  ResponseVaultGrantRejectedError,
  ResponseVaultRejectionBlockedError,
  ResponseVaultRejectionPendingError,
  ResponseVaultSettlementPendingError,
  type ResponseVaultConfig,
  type ResponseVaultGrant,
} from './response-vault-contract'

export class ResponseVault extends ResponseVaultNavigation {
  constructor(config: ResponseVaultConfig) {
    super(config)
  }
}
