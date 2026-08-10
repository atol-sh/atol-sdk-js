import { createDPoPKeyManager } from '../dpop/dpop'
import {
  assertCredentialGenerationSnapshot,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import {
  codeChallenge,
  exactCurrentCallback,
  randomOpaque,
  sameIntent,
  validateIntent,
} from './response-vault-config'
import {
  ResponseVaultAuthenticatedTerminalError,
  ResponseVaultDeliveryUnavailableError,
  ResponseVaultGrantRejectedError,
  ResponseVaultRejectionBlockedError,
  type PushedAuthorizationResponse,
  type ResponseVaultGrant,
} from './response-vault-contract'
import { ResponseVaultRelay } from './response-vault-relay'
import {
  bindResponseVaultBootstrap,
  bindResponseVaultBootstrapAttempt,
  bindResponseVaultPAR,
  claimResponseVaultNavigation,
  claimResponseVaultRejection,
  discardResponseVaultAuthorization,
  markResponseVaultInitialized,
  markResponseVaultInitializing,
  releaseResponseVaultExecution,
  stageResponseVaultAuthorization,
  ResponseVaultAuthorizationBusyError,
  ResponseVaultExecutionBusyError,
  type ResponseVaultAuthorization,
  type ResponseVaultIntent,
} from './response-vault-storage'
import { relayOAuthError } from './response-vault-wire'
import { OAuthProtocolError } from './token-recovery'

export abstract class ResponseVaultAdmission extends ResponseVaultRelay {
  protected async start(
    mode: 'interactive' | 'iframe',
    intent: ResponseVaultIntent,
    expectedGeneration?: CredentialGenerationSnapshot,
  ): Promise<ResponseVaultAuthorization> {
    validateIntent(intent, this.config.redirectUri)
    if (expectedGeneration) {
      assertCredentialGenerationSnapshot(this.config, expectedGeneration)
    }
    const lifecycleEpoch = this.lifecycleEpoch()
    const executionOwner = randomOpaque()
    const existing = await this.activeAuthorization(lifecycleEpoch)
    if (existing) {
      this.assertExpectedGeneration(existing, expectedGeneration)
    }
    this.assertLifecycle(lifecycleEpoch)
    if (expectedGeneration) {
      assertCredentialGenerationSnapshot(this.config, expectedGeneration)
    }
    let authorization: ResponseVaultAuthorization | undefined
    try {
      if (existing) {
        if (existing.mode !== mode || !sameIntent(existing.intent, intent)) {
          throw new ResponseVaultAuthorizationBusyError()
        }
        if (
          existing.status === 'par_pending' ||
          existing.status === 'pushed'
        ) {
          authorization = await this.claimExecution(
            existing,
            executionOwner,
            [existing.status],
          )
        } else if (existing.status === 'prepared') {
          authorization = await this.claimExecution(
            existing,
            executionOwner,
            ['prepared'],
          )
        } else if (
          existing.status === 'initializing' ||
          existing.status === 'initialized'
        ) {
          const cancellation = await claimResponseVaultRejection(
            existing,
            executionOwner,
            [existing.status],
            this.executionLeaseDuration(),
          )
          await this.rejectAuthorization(cancellation)
          throw new ResponseVaultGrantRejectedError()
        } else if (existing.status === 'navigating') {
          throw new ResponseVaultAuthorizationBusyError()
        } else if (
          existing.status === 'awaiting_ack' ||
          existing.status === 'publishing' ||
          existing.status === 'finalizing' ||
          existing.status === 'adopted'
        ) {
          if (
            this.pendingSettlement?.referenceId === existing.reference.id
          ) {
            throw new ResponseVaultAuthorizationBusyError()
          }
          const settlement = existing.settlement
          if (!settlement) {
            throw new Error(
              'response vault: durable settlement classification is unavailable',
            )
          }
          const cancellation = await claimResponseVaultRejection(
            existing,
            executionOwner,
            [existing.status],
            this.executionLeaseDuration(),
            true,
            false,
          )
          await this.rejectAuthorization(cancellation)
          if (settlement.kind === 'error') {
            throw relayOAuthError(settlement.errorCode)
          }
          throw new ResponseVaultDeliveryUnavailableError(
            existing.intent.returnTo,
          )
        } else if (
          existing.status === 'rejecting' ||
          existing.status === 'reject_retry'
        ) {
          const cancellation = await claimResponseVaultRejection(
            existing,
            executionOwner,
            [existing.status],
            this.executionLeaseDuration(),
          )
          await this.rejectAuthorization(cancellation)
          throw new ResponseVaultGrantRejectedError()
        } else {
          throw new ResponseVaultAuthorizationBusyError()
        }
      } else {
        // Resolve immutable registration authority before creating durable
        // custody. A discovery failure proves no bootstrap request was sent,
        // so it must not leave an ambiguous prepared owner behind.
        await this.endpointRegistry()
        this.assertLifecycle(lifecycleEpoch)
        if (expectedGeneration) {
          assertCredentialGenerationSnapshot(this.config, expectedGeneration)
        }
        const dpopKey = await createDPoPKeyManager()
        this.assertLifecycle(lifecycleEpoch)
        if (expectedGeneration) {
          assertCredentialGenerationSnapshot(this.config, expectedGeneration)
        }
        if (!dpopKey) {
          throw new Error(
            'response vault: WebCrypto could not create a DPoP key',
          )
        }
        const codeVerifier = randomOpaque()
        const challenge = await codeChallenge(codeVerifier)
        this.assertLifecycle(lifecycleEpoch)
        authorization = await stageResponseVaultAuthorization(
          dpopKey,
          this.config,
          mode,
          intent,
          lifecycleEpoch,
          {
            state: randomOpaque(),
            nonce: randomOpaque(),
            codeVerifier,
            codeChallenge: challenge,
            tabSecret: randomOpaque(),
            parIdempotencyKey: randomOpaque(),
            cancellationSecret: randomOpaque(),
          },
          expectedGeneration,
        )
        authorization = await this.claimExecution(
          authorization,
          executionOwner,
          ['prepared'],
        )
        this.assertExpectedGeneration(authorization, expectedGeneration)
        this.setActive(authorization.reference)
      }
      if (authorization.status === 'prepared') {
        if (
          !Number.isSafeInteger(authorization.phaseExpiresAt) ||
          (authorization.phaseExpiresAt as number) <= Date.now()
        ) {
          await this.bootstrapClient(authorization, 'terminal_only')
          throw new Error(
            'response vault: terminal bootstrap classification returned',
          )
        }
        let bootstrap = await this.bootstrapClient(authorization)
        if ('attemptCapability' in bootstrap) {
          authorization = await bindResponseVaultBootstrapAttempt(
            authorization,
            bootstrap.attemptCapability,
            Math.min(
              bootstrap.attemptExpiresAt,
              authorization.phaseExpiresAt as number,
            ),
          )
          this.assertExpectedGeneration(
            authorization,
            expectedGeneration,
          )
          bootstrap = await this.bootstrapClient(authorization)
          if ('attemptCapability' in bootstrap) {
            throw new Error(
              'response vault: repeated bootstrap attempt challenge',
            )
          }
        }
        this.assertExpectedGeneration(authorization, expectedGeneration)
        authorization = await bindResponseVaultBootstrap(
          authorization,
          bootstrap.csrfToken,
          bootstrap.bootstrapTerminalProof,
          bootstrap.bootstrapExpiresAt,
        )
      }

      if (authorization.status === 'par_pending') {
        if (!authorization.csrfToken) {
          throw new Error('response vault: PAR retry binding is incomplete')
        }
        let pushed: PushedAuthorizationResponse
        try {
          pushed = await this.pushAuthorization(
            authorization,
            authorization.csrfToken,
          )
        } catch (error) {
          const conclusivelyUnbound =
            error instanceof ResponseVaultAuthorizationBusyError ||
            error instanceof ResponseVaultAuthenticatedTerminalError ||
            (error instanceof OAuthProtocolError &&
              error.code !== 'temporarily_unavailable')
          if (conclusivelyUnbound) {
            this.clearActive(authorization.reference)
            await discardResponseVaultAuthorization(authorization)
            authorization = undefined
          }
          throw error
        }
        this.assertExpectedGeneration(authorization, expectedGeneration)
        let bindError: unknown
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            authorization = await bindResponseVaultPAR(
              authorization,
              pushed.transactionId,
              pushed.requestUri,
              pushed.csrfToken,
              pushed.terminalProof,
              pushed.requestUriExpiresAt,
              pushed.transactionExpiresAt,
            )
            bindError = undefined
            break
          } catch (error) {
            bindError = error
            if (attempt < 2) {
              await this.waitForRetry(
                100 * 2 ** attempt,
                authorization.lifecycleEpoch,
              )
            }
          }
        }
        if (bindError) {
          if (bindError instanceof ResponseVaultExecutionBusyError) {
            throw bindError
          }
          await this.rejectUnboundAuthorization(
            authorization,
            pushed,
            bindError,
          )
        }
      }
      if (
        authorization.status !== 'pushed' ||
        !authorization.requestUri ||
        !Number.isSafeInteger(authorization.phaseExpiresAt)
      ) {
        throw new ResponseVaultAuthorizationBusyError()
      }
      if ((authorization.phaseExpiresAt as number) <= Date.now()) {
        return this.rejectAfterFailure(
          authorization,
          new OAuthProtocolError(
            'invalid_request',
            'response vault: pushed authorization request URI expired',
          ),
        )
      }
      this.assertExpectedGeneration(authorization, expectedGeneration)
      const requestUri = authorization.requestUri
      authorization = await markResponseVaultInitializing(authorization)
      await this.initializeIssuer(requestUri)
      this.assertExpectedGeneration(authorization, expectedGeneration)
      authorization = await markResponseVaultInitialized(authorization)
      this.assertExpectedGeneration(authorization, expectedGeneration)
      return authorization
    } catch (error) {
      if (error instanceof ResponseVaultExecutionBusyError) {
        throw error
      }
      if (authorization?.transactionId && authorization.csrfToken) {
        return this.rejectAfterFailure(authorization, error)
      }
      if (authorization?.executionClaim) {
        if (error instanceof ResponseVaultAuthenticatedTerminalError) {
          this.clearActive(authorization.reference)
          await discardResponseVaultAuthorization(authorization)
        } else if (
          authorization.status === 'prepared' ||
          authorization.status === 'par_pending'
        ) {
          await releaseResponseVaultExecution(
            authorization,
            true,
            false,
          )
        } else {
          this.clearActive(authorization.reference)
          await discardResponseVaultAuthorization(authorization)
        }
      }
      throw error
    }
  }

  async completeInteractive(
    expectedGeneration?: CredentialGenerationSnapshot,
  ): Promise<ResponseVaultGrant> {
    if (!exactCurrentCallback(this.config.redirectUri)) {
      throw new Error('response vault: current URL is not the clean callback')
    }
    const lifecycleEpoch = this.lifecycleEpoch()
    let authorization = await this.activeAuthorization(lifecycleEpoch)
    if (!authorization) {
      throw new Error('response vault: no same-tab authorization is pending')
    }
    this.assertExpectedGeneration(authorization, expectedGeneration)
    if (authorization.mode !== 'interactive') {
      throw new Error('response vault: callback transaction mode mismatch')
    }
    if (
      this.pendingSettlement?.referenceId === authorization.reference.id
    ) {
      if (this.pendingSettlement.kind === 'success') {
        return this.pendingSettlement.grant
      }
      return this.relay(this.pendingSettlement.authorization)
    }
    const executionOwner = randomOpaque()
    if (authorization.status === 'navigating') {
      authorization = await claimResponseVaultNavigation(
        authorization,
        executionOwner,
        'interactive',
        this.executionLeaseDuration(),
      )
    } else if (
      authorization.status === 'redeeming' ||
      authorization.status === 'relay_retry'
    ) {
      authorization = await this.claimExecution(
        authorization,
        executionOwner,
        [authorization.status],
      )
    } else if (
      authorization.status === 'initializing' ||
      authorization.status === 'initialized'
    ) {
      const cancellation = await claimResponseVaultRejection(
        authorization,
        executionOwner,
        [authorization.status],
        this.executionLeaseDuration(),
      )
      await this.rejectAuthorization(cancellation)
      throw new ResponseVaultGrantRejectedError()
    } else if (
      authorization.status === 'awaiting_ack' ||
      authorization.status === 'publishing' ||
      authorization.status === 'finalizing' ||
      authorization.status === 'adopted'
    ) {
      const settlement = authorization.settlement
      if (!settlement) {
        throw new Error(
          'response vault: durable settlement classification is unavailable',
        )
      }
      const returnTo = authorization.intent.returnTo
      const cancellation = await claimResponseVaultRejection(
        authorization,
        executionOwner,
        [authorization.status],
        this.executionLeaseDuration(),
      )
      await this.rejectAuthorization(cancellation)
      if (settlement.kind === 'error') {
        throw relayOAuthError(settlement.errorCode)
      }
      throw new ResponseVaultDeliveryUnavailableError(returnTo)
    } else if (
      authorization.status === 'rejecting' ||
      authorization.status === 'reject_retry'
    ) {
      const cancellation = await claimResponseVaultRejection(
        authorization,
        executionOwner,
        [authorization.status],
        this.executionLeaseDuration(),
      )
      await this.rejectAuthorization(cancellation)
      throw new ResponseVaultGrantRejectedError()
    } else if (authorization.status === 'reject_blocked') {
      throw new ResponseVaultRejectionBlockedError(
        new Error('response vault: rejection remains blocked'),
      )
    } else {
      throw new Error(
        'response vault: callback transaction is not initialized',
      )
    }
    return this.relay(authorization)
  }
}
