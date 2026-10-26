import {
  CredentialGenerationInvalidatedError,
  CredentialGenerationSupersededError,
} from './credential-generation'
import {
  ResponseVaultAuthorizationBindingMismatchError,
  ResponseVaultAuthorizationInvalidatedError,
  ResponseVaultCleanupPendingError,
  ResponseVaultGrantRejectedError,
  ResponseVaultRejectionBlockedError,
  ResponseVaultRejectionPendingError,
} from './response-vault-contract'
import {
  ResponseVaultAuthorizationBusyError,
  ResponseVaultExecutionBusyError,
} from './response-vault-model'

export function closedCustodyError(error: unknown): Error {
  try {
    if (
      error instanceof CredentialGenerationInvalidatedError ||
      error instanceof CredentialGenerationSupersededError
    ) {
      return new ResponseVaultAuthorizationInvalidatedError()
    }
    if (error instanceof ResponseVaultExecutionBusyError) {
      return new ResponseVaultExecutionBusyError()
    }
    if (error instanceof ResponseVaultAuthorizationBusyError) {
      return new ResponseVaultAuthorizationBusyError()
    }
    if (error instanceof ResponseVaultAuthorizationBindingMismatchError) {
      return new ResponseVaultAuthorizationBindingMismatchError()
    }
    if (error instanceof ResponseVaultAuthorizationInvalidatedError) {
      return new ResponseVaultAuthorizationInvalidatedError()
    }
    if (error instanceof ResponseVaultCleanupPendingError) {
      return new ResponseVaultCleanupPendingError(undefined)
    }
    if (error instanceof ResponseVaultGrantRejectedError) {
      return new ResponseVaultGrantRejectedError()
    }
    if (error instanceof ResponseVaultRejectionBlockedError) {
      return new ResponseVaultRejectionBlockedError(undefined)
    }
    if (error instanceof ResponseVaultRejectionPendingError) {
      return new ResponseVaultRejectionPendingError(undefined)
    }
  } catch {
    // Arbitrary caught values may be hostile proxies. Classification must
    // never inspect or retain them beyond this closed boundary.
  }
  return new ResponseVaultCleanupPendingError(undefined)
}
