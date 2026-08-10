import { randomOpaque } from './response-vault-config'
import {
  RESPONSE_VAULT_PROTOCOL_VERSION,
  ResponseVaultCleanupPendingError,
  ResponseVaultRejectionBlockedError,
  ResponseVaultRejectionPendingError,
  ResponseVaultSettlementPendingError,
} from './response-vault-contract'
import { ResponseVaultLoginCancellation } from './response-vault-login-cancellation'
import {
  beginResponseVaultFinalization,
  markResponseVaultAdopted,
  markResponseVaultPublishing,
  releaseResponseVaultAuthorization,
  releaseResponseVaultExecution,
  retryResponseVaultFinalization,
  type ResponseVaultAuthorization,
} from './response-vault-storage'
import { releaseExecutionLockIfHeld } from './response-vault-storage-lock'
import { protocolError, responseEnvelope } from './response-vault-wire'
import { NetworkError, OAuthProtocolError } from './token-recovery'

export abstract class ResponseVaultSettlement
  extends ResponseVaultLoginCancellation {
  protected async acknowledge(
    authorization: ResponseVaultAuthorization,
  ): Promise<ResponseVaultAuthorization> {
    let current = authorization
    let retainExecutionLock = false
    try {
      if (
        current.status !== 'awaiting_ack' ||
        !current.transactionId ||
        !current.csrfToken ||
        !current.settlement
      ) {
        throw new Error(
          'response vault: acknowledgement binding is incomplete',
        )
      }
      const endpoints = await this.endpointRegistry()
      current = await this.claimExecution(
        current,
        current.executionClaim?.owner ?? randomOpaque(),
        ['awaiting_ack'],
      )
      let lastError: unknown
      for (let attempt = 0; attempt < 3; attempt++) {
        this.assertAuthorizationCurrent(current)
        try {
          const response = await this.postJSON(
            endpoints.acknowledgement,
            {
              version: RESPONSE_VAULT_PROTOCOL_VERSION,
              transaction_id: current.transactionId,
              tab_secret: current.tabSecret,
              cancellation_secret: current.cancellationSecret,
            },
            'authorization acknowledgement',
            'same-origin',
          )
          if (response.status !== 204 || (await response.text()) !== '') {
            if (response.status !== 204) {
              throw protocolError(
                response.status,
                await responseEnvelope(response),
                'authorization acknowledgement',
              )
            }
            throw new Error(
              'response vault: acknowledgement response is invalid',
            )
          }
          this.assertAuthorizationCurrent(current)
          current = await markResponseVaultPublishing(current)
          retainExecutionLock = true
          return current
        } catch (error) {
          lastError = error
          const retryable =
            error instanceof NetworkError ||
            (error instanceof OAuthProtocolError &&
              error.code === 'temporarily_unavailable')
          if (!retryable) {
            await this.rejectAuthorization(current)
            throw error
          }
          if (attempt < 2) {
            await this.waitForRetry(
              100 * 2 ** attempt,
              current.lifecycleEpoch,
            )
          }
        }
      }
      const released = await releaseResponseVaultExecution(current)
      if (
        this.pendingSettlement?.kind === 'error' &&
        this.pendingSettlement.referenceId === released.reference.id
      ) {
        this.pendingSettlement.authorization = released
      }
      throw new ResponseVaultSettlementPendingError(lastError, released)
    } finally {
      if (!retainExecutionLock) {
        await releaseExecutionLockIfHeld(
          current.reference,
          current.executionClaim,
        )
      }
    }
  }

  protected async finalize(
    initial: ResponseVaultAuthorization,
  ): Promise<ResponseVaultAuthorization> {
    const authorization = await this.prepareFinalization(initial)
    if (authorization.status === 'adopted') return authorization
    return this.finalizePrepared(authorization)
  }

  protected async prepareFinalization(
    initial: ResponseVaultAuthorization,
  ): Promise<ResponseVaultAuthorization> {
    let authorization = await this.claimExecution(
      initial,
      initial.executionClaim?.owner ?? randomOpaque(),
      ['publishing', 'finalizing', 'adopted'],
    )
    let retainExecutionLock = false
    try {
      if (authorization.status === 'publishing') {
        authorization = await beginResponseVaultFinalization(authorization)
      } else if (authorization.status === 'finalizing') {
        authorization = await retryResponseVaultFinalization(authorization)
      } else if (authorization.status !== 'adopted') {
        throw new Error('response vault: finalization binding is incomplete')
      }
      retainExecutionLock = true
      return authorization
    } finally {
      if (!retainExecutionLock) {
        await releaseExecutionLockIfHeld(
          authorization.reference,
          authorization.executionClaim,
        )
      }
    }
  }

  protected async finalizePrepared(
    authorization: ResponseVaultAuthorization,
  ): Promise<ResponseVaultAuthorization> {
    let retainExecutionLock = false
    try {
      if (authorization.status !== 'finalizing') {
        throw new Error('response vault: finalization binding is incomplete')
      }
      const endpoints = await this.endpointRegistry()
      let lastError: unknown
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          this.assertAuthorizationCurrent(authorization)
          const response = await this.postJSON(
            endpoints.finalization,
            {
              version: RESPONSE_VAULT_PROTOCOL_VERSION,
              transaction_id: authorization.transactionId,
              tab_secret: authorization.tabSecret,
              cancellation_secret: authorization.cancellationSecret,
            },
            'authorization finalization',
            'same-origin',
          )
          if (response.status !== 204 || (await response.text()) !== '') {
            if (response.status !== 204) {
              throw protocolError(
                response.status,
                await responseEnvelope(response),
                'authorization finalization',
              )
            }
            throw new Error(
              'response vault: finalization response is invalid',
            )
          }
          try {
            this.assertAuthorizationCurrent(authorization)
          } catch (error) {
            await this.rejectAuthorization(authorization)
            throw error
          }
          const adopted = await markResponseVaultAdopted(authorization)
          retainExecutionLock = true
          return adopted
        } catch (error) {
          if (
            error instanceof ResponseVaultRejectionPendingError ||
            error instanceof ResponseVaultRejectionBlockedError
          ) {
            throw error
          }
          try {
            this.assertAuthorizationCurrent(authorization)
          } catch (staleError) {
            await this.rejectAuthorization(authorization)
            throw staleError
          }
          lastError = error
          if (attempt < 2) {
            await this.waitForRetry(
              100 * 2 ** attempt,
              authorization.lifecycleEpoch,
            )
          }
        }
      }
      const released = await releaseResponseVaultExecution(authorization)
      if (
        this.pendingSettlement?.kind === 'error' &&
        this.pendingSettlement.referenceId === released.reference.id
      ) {
        this.pendingSettlement.authorization = released
      }
      throw new ResponseVaultSettlementPendingError(lastError, released)
    } finally {
      if (!retainExecutionLock) {
        await releaseExecutionLockIfHeld(
          authorization.reference,
          authorization.executionClaim,
        )
      }
    }
  }

  protected async completePublication(
    authorization: ResponseVaultAuthorization,
  ): Promise<void> {
    try {
      this.clearActive(authorization.reference)
    } catch {
      // The global durable slot is authoritative and is released below.
    }
    try {
      await releaseResponseVaultAuthorization(authorization)
    } catch (error) {
      throw new ResponseVaultCleanupPendingError(error)
    }
  }
}
