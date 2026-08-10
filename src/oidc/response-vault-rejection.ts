import { randomOpaque } from './response-vault-config'
import {
  REJECTION_CLAIM_STATUSES,
  REJECT_PATH,
  RESPONSE_VAULT_PROTOCOL_VERSION,
  ResponseVaultCleanupPendingError,
  ResponseVaultRejectionBlockedError,
  ResponseVaultRejectionPendingError,
  type PushedAuthorizationResponse,
} from './response-vault-contract'
import {
  blockResponseVaultRejection,
  claimResponseVaultRejection,
  claimResponseVaultTerminalProbe,
  discardResponseVaultAuthorization,
  discardResponseVaultCancellation,
  releaseResponseVaultCancellationExecution,
  resetResponseVaultRejection,
  retryResponseVaultRejection,
  type ResponseVaultAuthorization,
  type ResponseVaultCancellation,
  type ResponseVaultCustody,
  ResponseVaultExecutionBusyError,
} from './response-vault-storage'
import {
  releaseExecutionLockIfHeld,
  responseVaultExecutionLockHeld,
} from './response-vault-storage-lock'
import { ResponseVaultTransport } from './response-vault-transport'
import {
  isAuthenticatedNonterminalResponse,
  isAuthenticatedTerminalResponse,
  protocolError,
  responseEnvelope,
} from './response-vault-wire'
import { OAuthProtocolError } from './token-recovery'

export abstract class ResponseVaultRejection extends ResponseVaultTransport {
  protected async rejectAuthorization(
    initial: ResponseVaultCustody,
  ): Promise<void> {
    if (this.rejectedReferences.has(initial.reference.id)) return
    const existing = this.rejectionFlights.get(initial.reference.id)
    if (existing) return existing
    const flight = this.performRejection(initial).finally(() => {
      this.rejectionFlights.delete(initial.reference.id)
    })
    this.rejectionFlights.set(initial.reference.id, flight)
    return flight
  }

  protected async probePublishedTerminal(
    initial: ResponseVaultCancellation,
  ): Promise<void> {
    if (!initial.terminalProof) {
      throw new Error(
        'response vault: terminal probe proof is unavailable',
      )
    }
    let cancellation: ResponseVaultCancellation | undefined
    try {
      cancellation = await claimResponseVaultTerminalProbe(
        initial,
        randomOpaque(),
        this.executionLeaseDuration(),
      )
      let lastError: unknown
      for (let attempt = 0; attempt < 3; attempt++) {
        let authenticatedTerminal = false
        let authenticatedNonterminal = false
        try {
          const response = await this.postJSON(
            `${this.clientOrigin}${REJECT_PATH}`,
            {
              version: RESPONSE_VAULT_PROTOCOL_VERSION,
              mode: 'terminal_only',
              transaction_id: cancellation.transactionId,
              client_id: cancellation.binding.clientId,
              tab_secret: cancellation.tabSecret,
              cancellation_secret: cancellation.cancellationSecret,
              terminal_proof: cancellation.terminalProof,
            },
            'authorization terminal probe',
            'same-origin',
          )
          const envelope = await responseEnvelope(response)
          authenticatedTerminal = isAuthenticatedTerminalResponse(
            response,
            envelope,
          )
          authenticatedNonterminal = isAuthenticatedNonterminalResponse(
            response,
            envelope,
          )
          if (!authenticatedTerminal && !authenticatedNonterminal) {
            throw protocolError(
              response.status,
              envelope,
              'authorization terminal probe',
            )
          }
        } catch (error) {
          lastError = error
          if (attempt < 2) {
            await this.waitForRetry(100 * 2 ** attempt)
          }
          continue
        }
        if (authenticatedTerminal) {
          try {
            await discardResponseVaultCancellation(cancellation)
          } catch (error) {
            throw new ResponseVaultCleanupPendingError(error)
          }
          this.rejectedReferences.add(cancellation.reference.id)
          return
        }
        try {
          await releaseResponseVaultCancellationExecution(cancellation)
        } catch (error) {
          throw new ResponseVaultCleanupPendingError(error)
        }
        return
      }
      try {
        await releaseResponseVaultCancellationExecution(cancellation)
      } catch (releaseError) {
        throw new ResponseVaultCleanupPendingError(releaseError)
      }
      throw new ResponseVaultCleanupPendingError(lastError)
    } finally {
      const custody = cancellation ?? initial
      await releaseExecutionLockIfHeld(
        custody.reference,
        custody.executionClaim,
      )
    }
  }

  private async performRejection(
    initial: ResponseVaultCustody,
  ): Promise<void> {
    let authorization: ResponseVaultCancellation | undefined
    let completed = false
    try {
      const preclaimed = responseVaultExecutionLockHeld(
        initial.reference,
        initial.executionClaim,
      )
      if (preclaimed) {
        this.pendingRejectionCustody.delete(initial.reference.id)
      }
      const pending = preclaimed
        ? initial
        : this.pendingRejectionCustody.get(initial.reference.id) ?? initial
      authorization = await claimResponseVaultRejection(
        pending,
        pending.executionClaim?.owner ?? randomOpaque(),
        REJECTION_CLAIM_STATUSES,
        this.executionLeaseDuration(),
        false,
        false,
      )

      const rejectionEndpoint = `${this.clientOrigin}${REJECT_PATH}`
      let lastError: unknown
      for (let attempt = 0; attempt < 3; attempt++) {
        if (authorization.status === 'reject_retry') {
          authorization = await retryResponseVaultRejection(authorization)
        }
        try {
          if (!authorization.transactionId) {
            throw new Error('response vault: rejection binding is incomplete')
          }
          const response = await this.postJSON(
            rejectionEndpoint,
            {
              version: RESPONSE_VAULT_PROTOCOL_VERSION,
              mode: 'reject',
              transaction_id: authorization.transactionId,
              tab_secret: authorization.tabSecret,
              cancellation_secret: authorization.cancellationSecret,
            },
            'authorization rejection',
            'same-origin',
          )
          if (response.status === 204 && (await response.text()) === '') {
            try {
              this.clearActive(authorization.reference)
            } catch {
              // The authoritative durable record is still released below.
            }
            this.clearPendingSettlement(authorization.reference)
            try {
              await discardResponseVaultCancellation(authorization)
            } catch (error) {
              throw new ResponseVaultRejectionPendingError(error)
            }
            this.pendingRejectionCustody.delete(authorization.reference.id)
            this.rejectedReferences.add(authorization.reference.id)
            completed = true
            return
          }
          if (response.status === 204) {
            throw new Error('response vault: rejection response is invalid')
          }
          const envelope = await responseEnvelope(response)
          const error = protocolError(
            response.status,
            envelope,
            'authorization rejection',
          )
          if (
            (response.status === 400 || response.status === 403) &&
            error instanceof OAuthProtocolError &&
            error.code === 'invalid_request'
          ) {
            const blocked = await blockResponseVaultRejection(authorization)
            authorization =
              await releaseResponseVaultCancellationExecution(blocked)
            throw new ResponseVaultRejectionBlockedError(error)
          }
          throw error
        } catch (error) {
          lastError = error
          if (error instanceof ResponseVaultRejectionBlockedError) {
            throw error
          }
          try {
            authorization = await resetResponseVaultRejection(authorization)
          } catch {
            throw new ResponseVaultRejectionPendingError(error)
          }
          if (attempt < 2) {
            await this.waitForRetry(100 * 2 ** attempt)
          }
        }
      }
      authorization =
        await releaseResponseVaultCancellationExecution(authorization)
      throw new ResponseVaultRejectionPendingError(lastError)
    } finally {
      const custody = authorization ?? initial
      try {
        await releaseExecutionLockIfHeld(
          custody.reference,
          custody.executionClaim,
        )
      } finally {
        if (!completed && authorization) {
          this.pendingRejectionCustody.set(
            authorization.reference.id,
            authorization,
          )
        }
      }
    }
  }

  protected async rejectUnboundAuthorization(
    initial: ResponseVaultAuthorization,
    pushed: PushedAuthorizationResponse,
    originalError: unknown,
  ): Promise<never> {
    if (!initial.executionClaim) {
      throw new ResponseVaultExecutionBusyError()
    }
    let authorization: ResponseVaultAuthorization | undefined
    try {
      authorization = await this.claimExecution(
        initial,
        initial.executionClaim.owner,
        ['par_pending'],
      )
      const rejectionEndpoint = `${this.clientOrigin}${REJECT_PATH}`
      let lastError: unknown
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const response = await this.postJSON(
            rejectionEndpoint,
            {
              version: RESPONSE_VAULT_PROTOCOL_VERSION,
              mode: 'reject',
              transaction_id: pushed.transactionId,
              tab_secret: authorization.tabSecret,
              cancellation_secret: authorization.cancellationSecret,
            },
            'authorization rejection',
            'same-origin',
          )
          if (response.status === 204 && (await response.text()) === '') {
            this.clearActive(authorization.reference)
            await discardResponseVaultAuthorization(authorization)
            throw originalError
          }
          if (response.status !== 204) {
            const error = protocolError(
              response.status,
              await responseEnvelope(response),
              'authorization rejection',
            )
            if (
              (response.status === 400 || response.status === 403) &&
              error instanceof OAuthProtocolError &&
              error.code === 'invalid_request'
            ) {
              throw new ResponseVaultRejectionBlockedError(error)
            }
            throw error
          }
          throw new Error('response vault: rejection response is invalid')
        } catch (error) {
          if (
            error === originalError ||
            error instanceof ResponseVaultRejectionBlockedError
          ) {
            throw error
          }
          lastError = error
          if (attempt < 2) {
            await this.waitForRetry(100 * 2 ** attempt)
          }
        }
      }
      throw new ResponseVaultRejectionPendingError(lastError)
    } finally {
      const custody = authorization ?? initial
      await releaseExecutionLockIfHeld(
        custody.reference,
        custody.executionClaim,
      )
    }
  }

  protected async rejectAfterFailure(
    authorization: ResponseVaultCustody,
    originalError: unknown,
  ): Promise<never> {
    await this.rejectAuthorization(authorization)
    throw originalError
  }
}
