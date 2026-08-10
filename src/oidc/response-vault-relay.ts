import { parseDPoPNonceHeader } from './silent-renew'
import {
  CANONICAL_OPAQUE,
  RESPONSE_VAULT_PROTOCOL_VERSION,
  ResponseVaultDeliveryUnavailableError,
  ResponseVaultGrantRejectedError,
  ResponseVaultSettlementPendingError,
  takeResponseVaultSettlementAuthorization,
  type PendingSettlement,
  type RelaySuccess,
  type ResponseVaultGrant,
} from './response-vault-contract'
import { ResponseVaultSettlement } from './response-vault-settlement'
import {
  beginResponseVaultRelay,
  bindResponseVaultAcknowledgement,
  recoverResponseVaultRelay,
  releaseResponseVaultExecution,
  resetResponseVaultRelay,
  retryResponseVaultRelay,
  type ResponseVaultAuthorization,
} from './response-vault-storage'
import { releaseExecutionLockIfHeld } from './response-vault-storage-lock'
import {
  protocolError,
  relayOAuthError,
  relaySuccess,
  responseEnvelope,
  terminalRelayError,
} from './response-vault-wire'
import { hasExactMembers } from './strict-json'
import { NetworkError, OAuthProtocolError } from './token-recovery'

export abstract class ResponseVaultRelay extends ResponseVaultSettlement {
  private async relayRequest(
    authorization: ResponseVaultAuthorization,
    nonce?: string,
  ): Promise<Response> {
    if (
      !authorization.transactionId ||
      !authorization.csrfToken ||
      !CANONICAL_OPAQUE.test(authorization.transactionId) ||
      !CANONICAL_OPAQUE.test(authorization.csrfToken)
    ) {
      throw new Error('response vault: relay binding is incomplete')
    }
    this.assertAuthorizationCurrent(authorization)
    const endpoints = await this.endpointRegistry()
    this.assertAuthorizationCurrent(authorization)
    const proof = await authorization.dpopKey.signProof(
      'POST',
      endpoints.token,
      nonce ? { nonce } : undefined,
    )
    this.assertAuthorizationCurrent(authorization)
    return this.postJSON(
      endpoints.relay,
      {
        version: RESPONSE_VAULT_PROTOCOL_VERSION,
        transaction_id: authorization.transactionId,
        tab_secret: authorization.tabSecret,
        code_verifier: authorization.codeVerifier,
        dpop_proof: proof,
      },
      'authorization relay',
      'same-origin',
      authorization.csrfToken,
    )
  }

  private async recoverableRelayRequest(
    authorization: ResponseVaultAuthorization,
    nonce?: string,
  ): Promise<Response> {
    try {
      return await this.relayRequest(authorization, nonce)
    } catch (error) {
      try {
        this.assertAuthorizationCurrent(authorization)
      } catch {
        return await this.rejectAfterFailure(authorization, error)
      }
      if (!(error instanceof NetworkError)) {
        return await this.rejectAfterFailure(authorization, error)
      }
      const retry = await resetResponseVaultRelay(authorization)
      await releaseResponseVaultExecution(retry)
      throw error
    }
  }

  private async readRelayEnvelope(
    response: Response,
    authorization: ResponseVaultAuthorization,
  ): Promise<Record<string, unknown>> {
    try {
      const envelope = await responseEnvelope(response)
      this.assertAuthorizationCurrent(authorization)
      return envelope
    } catch (error) {
      if (error instanceof NetworkError) {
        try {
          this.assertAuthorizationCurrent(authorization)
        } catch {
          return await this.rejectAfterFailure(authorization, error)
        }
        const retry = await resetResponseVaultRelay(authorization)
        await releaseResponseVaultExecution(retry)
      } else {
        return await this.rejectAfterFailure(authorization, error)
      }
      throw error
    }
  }

  protected async relay(
    initial: ResponseVaultAuthorization,
  ): Promise<ResponseVaultGrant> {
    let authorization = initial
    let retainExecutionLock = false
    try {
      if (
        authorization.status === 'rejecting' ||
        authorization.status === 'reject_retry' ||
        authorization.status === 'reject_blocked'
      ) {
        await this.rejectAuthorization(authorization)
        throw new ResponseVaultGrantRejectedError()
      }
      if (
        this.pendingSettlement?.referenceId === authorization.reference.id
      ) {
        const pending = this.pendingSettlement
        if (pending.kind === 'success') {
          retainExecutionLock = true
          return pending.grant
        }
        if (authorization.status === 'awaiting_ack') {
          authorization = await this.acknowledge(authorization)
        }
        if (
          authorization.status === 'publishing' ||
          authorization.status === 'finalizing'
        ) {
          authorization = await this.finalize(authorization)
        }
        if (authorization.status !== 'adopted') {
          throw new Error(
            'response vault: terminal settlement state is invalid',
          )
        }
        await this.completePublication(authorization)
        if (this.pendingSettlement === pending) {
          this.pendingSettlement = null
        }
        throw pending.error
      }
      if (authorization.status === 'awaiting_ack') {
        const settlement = authorization.settlement
        if (!settlement) {
          throw new Error(
            'response vault: acknowledgement settlement is unavailable',
          )
        }
        await this.rejectAuthorization(authorization)
        if (settlement.kind === 'error') {
          throw relayOAuthError(settlement.errorCode)
        }
        throw new ResponseVaultDeliveryUnavailableError(
          authorization.intent.returnTo,
        )
      }

      switch (authorization.status) {
        case 'initialized':
          authorization = await beginResponseVaultRelay(authorization)
          break
        case 'relay_retry':
          authorization = await retryResponseVaultRelay(authorization)
          break
        case 'redeeming':
          authorization = await recoverResponseVaultRelay(authorization)
          authorization = await retryResponseVaultRelay(authorization)
          break
        default:
          throw new Error('response vault: relay transaction state is invalid')
      }
    this.assertAuthorizationCurrent(authorization)
    let response = await this.recoverableRelayRequest(authorization)
    this.assertAuthorizationCurrent(authorization)
    let envelope = await this.readRelayEnvelope(response, authorization)
    if (response.status === 400 && envelope.error === 'use_dpop_nonce') {
      if (
        !hasExactMembers(envelope, ['error', 'error_description']) ||
        typeof envelope.error_description !== 'string' ||
        envelope.error_description.length === 0 ||
        envelope.error_description.length > 512
      ) {
        return await this.rejectAfterFailure(
          authorization,
          new Error('response vault: DPoP nonce challenge is malformed'),
        )
      }
      let nonce: string | undefined
      try {
        nonce = parseDPoPNonceHeader(response.headers)
      } catch (error) {
        return await this.rejectAfterFailure(authorization, error)
      }
      if (!nonce) {
        return await this.rejectAfterFailure(
          authorization,
          new Error('response vault: DPoP nonce challenge is malformed'),
        )
      }
      this.assertAuthorizationCurrent(authorization)
      response = await this.recoverableRelayRequest(authorization, nonce)
      this.assertAuthorizationCurrent(authorization)
      envelope = await this.readRelayEnvelope(response, authorization)
    }

    if (response.status === 503) {
      const retry = await resetResponseVaultRelay(authorization)
      await releaseResponseVaultExecution(retry)
      throw protocolError(
        response.status,
        envelope,
        'authorization relay',
      )
    }
    if (response.status === 400) {
      const terminal = terminalRelayError(envelope)
      if (terminal) {
        this.assertAuthorizationCurrent(authorization)
        try {
          authorization = await bindResponseVaultAcknowledgement(
            authorization,
            terminal.csrfToken,
            { kind: 'error', errorCode: terminal.code },
          )
        } catch (error) {
          return await this.rejectAfterFailure(authorization, error)
        }
        const pending: PendingSettlement = {
          kind: 'error',
          referenceId: authorization.reference.id,
          authorization,
          error: relayOAuthError(terminal.code),
        }
        this.pendingSettlement = pending
        try {
          authorization = await this.acknowledge(authorization)
        } catch (error) {
          if (error instanceof ResponseVaultSettlementPendingError) {
            const recovered =
              takeResponseVaultSettlementAuthorization(error)
            if (recovered) authorization = recovered
          }
          throw error
        }
        authorization = await this.finalize(authorization)
        await this.completePublication(authorization)
        if (this.pendingSettlement === pending) {
          this.pendingSettlement = null
        }
        throw pending.error
      }
      let error: Error
      if (
        hasExactMembers(envelope, ['error', 'error_description']) &&
        envelope.error === 'invalid_dpop_proof'
      ) {
        error = new OAuthProtocolError(
          'invalid_dpop_proof',
          'response vault: DPoP proof was rejected',
        )
      } else {
        error = protocolError(
          response.status,
          envelope,
          'authorization relay',
        )
      }
      return await this.rejectAfterFailure(authorization, error)
    }
    if (response.status !== 200) {
      return await this.rejectAfterFailure(
        authorization,
        protocolError(response.status, envelope, 'authorization relay'),
      )
    }

    let success: RelaySuccess
    try {
      success = relaySuccess(envelope)
    } catch (error) {
      return await this.rejectAfterFailure(authorization, error)
    }
    this.assertAuthorizationCurrent(authorization)
    try {
      authorization = await bindResponseVaultAcknowledgement(
        authorization,
        success.csrfToken,
        { kind: 'success' },
      )
    } catch (error) {
      return await this.rejectAfterFailure(authorization, error)
    }
    let responseNonce: string | undefined
    try {
      responseNonce = parseDPoPNonceHeader(response.headers)
    } catch (error) {
      return await this.rejectAfterFailure(authorization, error)
    }
    let settled = false
    let grant: ResponseVaultGrant
    grant = {
      tokens: success.tokens,
      nonce: authorization.nonce,
      dpopKey: authorization.dpopKey,
      dpopNonce: responseNonce,
      returnTo: authorization.intent.returnTo,
      credentialGeneration: authorization.credentialGeneration,
      acknowledge: async () => {
        if (settled) {
          throw new Error('response vault: grant is already settled')
        }
        if (
          this.pendingSettlement?.kind !== 'success' ||
          this.pendingSettlement.grant !== grant
        ) {
          throw new Error('response vault: grant was superseded')
        }
        if (
          authorization.status === 'publishing' ||
          authorization.status === 'finalizing' ||
          authorization.status === 'adopted'
        ) {
          return
        }
        try {
          authorization = await this.acknowledge(authorization)
        } catch (error) {
          if (error instanceof ResponseVaultSettlementPendingError) {
            const recovered =
              takeResponseVaultSettlementAuthorization(error)
            if (recovered) authorization = recovered
          }
          throw error
        }
      },
      finalize: async () => {
        if (settled) {
          throw new Error('response vault: grant is already settled')
        }
        if (
          this.pendingSettlement?.kind !== 'success' ||
          this.pendingSettlement.grant !== grant
        ) {
          throw new Error('response vault: grant was superseded')
        }
        try {
          authorization = await this.prepareFinalization(authorization)
          if (authorization.status === 'adopted') return
          authorization = await this.finalizePrepared(authorization)
        } catch (error) {
          if (error instanceof ResponseVaultSettlementPendingError) {
            const recovered =
              takeResponseVaultSettlementAuthorization(error)
            if (recovered) authorization = recovered
          }
          throw error
        }
      },
      completePublication: async () => {
        if (settled) {
          throw new Error('response vault: grant is already settled')
        }
        if (
          this.pendingSettlement?.kind !== 'success' ||
          this.pendingSettlement.grant !== grant
        ) {
          throw new Error('response vault: grant was superseded')
        }
        if (authorization.status !== 'adopted') {
          throw new Error(
            'response vault: grant is not finalized for publication',
          )
        }
        await this.completePublication(authorization)
        settled = true
        this.pendingSettlement = null
      },
      reject: async () => {
        if (settled) return
        await this.rejectAuthorization(authorization)
        settled = true
      },
    }
    this.pendingSettlement = {
      kind: 'success',
      referenceId: authorization.reference.id,
      grant,
    }
    retainExecutionLock = true
    return grant
    } finally {
      if (!retainExecutionLock) {
        await releaseExecutionLockIfHeld(
          authorization.reference,
          authorization.executionClaim,
        )
      }
    }
  }
}
