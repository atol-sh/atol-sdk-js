/**
 * Durable, authorization-specific custody for response-vault v1.
 *
 * This facade preserves the storage contract while the implementation keeps
 * persisted schema, validation, locking, migration, and lifecycle mutations
 * in dependency-safe modules.
 */

export {
  RESPONSE_VAULT_STATUS_SCHEMA,
  ResponseVaultAuthorizationBusyError,
  ResponseVaultExecutionBusyError,
  type ResponseVaultActiveCustody,
  type ResponseVaultAuthorization,
  type ResponseVaultAuthorizationMode,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultBinding,
  type ResponseVaultCancellation,
  type ResponseVaultCancellationBatch,
  type ResponseVaultCustody,
  type ResponseVaultExecutionClaim,
  type ResponseVaultExactGenerationSupersession,
  type ResponseVaultIntent,
  type ResponseVaultReference,
  type ResponseVaultRejectionProvenance,
  type ResponseVaultSecrets,
  type ResponseVaultSettlement,
} from './response-vault-model'
export {
  validResponseVaultACRValues,
  validResponseVaultBinding,
  validResponseVaultIntent,
  validResponseVaultScope,
  validResponseVaultTerminalProof,
} from './response-vault-storage-validation'
export {
  claimResponseVaultExecution,
  releaseResponseVaultCancellationExecution,
  releaseResponseVaultExecution,
  stageResponseVaultAuthorization,
} from './response-vault-storage-execution'
export {
  beginResponseVaultNavigation,
  claimResponseVaultNavigation,
  claimResponseVaultRejection,
  claimResponseVaultTerminalProbe,
} from './response-vault-storage-claims'
export {
  beginResponseVaultFinalization,
  beginResponseVaultRelay,
  bindResponseVaultAcknowledgement,
  bindResponseVaultBootstrapAttempt,
  bindResponseVaultBootstrap,
  bindResponseVaultPAR,
  markResponseVaultAdopted,
  markResponseVaultInitialized,
  markResponseVaultInitializing,
  markResponseVaultPublishing,
  recoverResponseVaultRelay,
  resetResponseVaultRelay,
  retryResponseVaultFinalization,
  retryResponseVaultRelay,
} from './response-vault-storage-transitions'
export {
  beginResponseVaultRejection,
  blockResponseVaultRejection,
  resetResponseVaultRejection,
  retryResponseVaultRejection,
} from './response-vault-storage-rejection'
export {
  loadActiveResponseVaultAuthorization,
  loadActiveResponseVaultAuthorizationForRejection,
  loadActiveResponseVaultCustody,
  loadResponseVaultAuthorization,
  loadResponseVaultAuthorizationForRejection,
} from './response-vault-storage-load'
export {
  discardResponseVaultAuthorization,
  discardResponseVaultCancellation,
  loadResponseVaultCompensations,
  loadResponseVaultLifecycleCancellations,
  loadResponseVaultTerminalProbes,
  releaseResponseVaultAuthorization,
  responseVaultCustodyReleased,
} from './response-vault-storage-lifecycle'
export { claimFailedInitializationTerminalProbe } from './response-vault-storage-failed-initialization'
