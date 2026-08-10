import { ResponseVaultContext } from './response-vault-context'
import {
  RESPONSE_VAULT_PROTOCOL_VERSION,
  ResponseVaultAuthenticatedTerminalError,
  type BootstrapAttemptChallenge,
  type BootstrapResponse,
  type PushedAuthorizationResponse,
} from './response-vault-contract'
import {
  ResponseVaultAuthorizationBusyError,
  type ResponseVaultAuthorization,
} from './response-vault-storage'
import {
  bootstrapAttemptChallenge,
  bootstrapResponse,
  expectProtocolResponse,
  isAuthenticatedNonterminalResponse,
  isAuthenticatedTerminalResponse,
  issuerBootstrapResponse,
  protocolError,
  pushedResponse,
  responseEnvelope,
} from './response-vault-wire'
import { NetworkError, OAuthProtocolError } from './token-recovery'

export abstract class ResponseVaultTransport extends ResponseVaultContext {
  protected async bootstrapClient(
    authorization: ResponseVaultAuthorization,
    mode: 'create' | 'terminal_only' = 'create',
  ): Promise<BootstrapResponse | BootstrapAttemptChallenge> {
    const endpoints = await this.endpointRegistry()
    const requestStartedAt = Date.now()
    const response = await this.postJSON(
      endpoints.bootstrap,
      {
        version: RESPONSE_VAULT_PROTOCOL_VERSION,
        mode,
        tab_secret: authorization.tabSecret,
        cancellation_secret: authorization.cancellationSecret,
        par_idempotency_key: authorization.parIdempotencyKey,
        ...(authorization.bootstrapAttemptCapability
          ? {
              attempt_capability:
                authorization.bootstrapAttemptCapability,
            }
          : {}),
      },
      'client bootstrap',
      'same-origin',
    )
    const envelope = await responseEnvelope(response)
    if (response.status === 201 && mode === 'create') {
      return bootstrapResponse(envelope, requestStartedAt)
    }
    if (
      response.status === 428 &&
      mode === 'create' &&
      !authorization.bootstrapAttemptCapability
    ) {
      return bootstrapAttemptChallenge(envelope, requestStartedAt)
    }
    if (isAuthenticatedTerminalResponse(response, envelope)) {
      throw new ResponseVaultAuthenticatedTerminalError()
    }
    if (
      mode === 'terminal_only' &&
      isAuthenticatedNonterminalResponse(response, envelope)
    ) {
      throw new ResponseVaultAuthorizationBusyError()
    }
    if (
      response.status === 410 ||
      envelope.error === 'authorization_terminal'
    ) {
      throw new NetworkError(
        'response vault: client bootstrap terminal classification is invalid',
      )
    }
    if (
      response.status === 409 &&
      envelope.error === 'authorization_nonterminal'
    ) {
      throw new NetworkError(
        'response vault: client bootstrap nonterminal classification is invalid',
      )
    }
    if (response.status === 201) {
      throw new NetworkError(
        'response vault: terminal bootstrap returned live authority',
      )
    }
    throw protocolError(response.status, envelope, 'client bootstrap')
  }

  protected async pushAuthorization(
    authorization: ResponseVaultAuthorization,
    csrf: string,
  ): Promise<PushedAuthorizationResponse> {
    if (!authorization.bootstrapTerminalProof) {
      throw new Error(
        'response vault: PAR bootstrap terminal proof is unavailable',
      )
    }
    const endpoints = await this.endpointRegistry()
    const body: Record<string, unknown> = {
      version: RESPONSE_VAULT_PROTOCOL_VERSION,
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scope,
      state: authorization.state,
      nonce: authorization.nonce,
      code_challenge: authorization.codeChallenge,
      code_challenge_method: 'S256',
      dpop_jkt: authorization.jkt,
      audience: this.config.audience,
      tab_secret: authorization.tabSecret,
      par_idempotency_key: authorization.parIdempotencyKey,
      cancellation_secret: authorization.cancellationSecret,
      bootstrap_terminal_proof: authorization.bootstrapTerminalProof,
      bootstrap_attempt_capability:
        authorization.bootstrapAttemptCapability,
    }
    if (authorization.intent.prompt !== undefined) {
      body.prompt = authorization.intent.prompt
    }
    if (authorization.intent.maxAge !== undefined) {
      body.max_age = authorization.intent.maxAge
    }
    if (authorization.intent.acrValues !== undefined) {
      body.acr_values = authorization.intent.acrValues
    }
    if (authorization.intent.organizationId !== undefined) {
      body.organization_id = authorization.intent.organizationId
    }
    let lastError: unknown
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const requestStartedAt = Date.now()
        const response = await this.postJSON(
          endpoints.pushedAuthorizationRequest,
          body,
          'pushed authorization',
          'same-origin',
          csrf,
        )
        const envelope = await responseEnvelope(response)
        if (response.status === 201) {
          return pushedResponse(envelope, requestStartedAt)
        }
        if (isAuthenticatedTerminalResponse(response, envelope)) {
          throw new ResponseVaultAuthenticatedTerminalError()
        }
        if (
          response.status === 410 ||
          envelope.error === 'authorization_terminal'
        ) {
          throw new NetworkError(
            'response vault: pushed authorization terminal proof is invalid',
          )
        }
        const error = protocolError(
          response.status,
          envelope,
          'pushed authorization',
        )
        if (response.status === 409) {
          throw new ResponseVaultAuthorizationBusyError()
        }
        if (
          response.status >= 400 &&
          response.status < 500 &&
          response.status !== 408 &&
          response.status !== 429
        ) {
          throw error
        }
        lastError = error
      } catch (error) {
        if (
          error instanceof ResponseVaultAuthorizationBusyError ||
          error instanceof ResponseVaultAuthenticatedTerminalError
        ) {
          throw error
        }
        if (
          error instanceof OAuthProtocolError &&
          error.code !== 'temporarily_unavailable'
        ) {
          throw error
        }
        lastError = error
      }
      if (attempt < 2) {
        await this.waitForRetry(
          100 * 2 ** attempt,
          authorization.lifecycleEpoch,
        )
      }
    }
    throw new NetworkError(
      'response vault: pushed authorization outcome is ambiguous',
      lastError,
    )
  }

  protected async initializeIssuer(requestUri: string): Promise<void> {
    const endpoints = await this.endpointRegistry()
    const issuerBootstrapStartedAt = Date.now()
    const bootstrap = await this.postJSON(
      endpoints.issuerBootstrap,
      { version: RESPONSE_VAULT_PROTOCOL_VERSION },
      'issuer bootstrap',
      'include',
    )
    const issuerBootstrap = issuerBootstrapResponse(
      await expectProtocolResponse(
        bootstrap,
        201,
        'issuer bootstrap',
      ),
      issuerBootstrapStartedAt,
    )
    const response = await this.postJSON(
      endpoints.authorizationInit,
      {
        version: RESPONSE_VAULT_PROTOCOL_VERSION,
        request_uri: requestUri,
      },
      'authorization init',
      'include',
      issuerBootstrap.csrfToken,
    )
    if (response.status !== 204 || (await response.text()) !== '') {
      if (response.status !== 204) {
        throw protocolError(
          response.status,
          await responseEnvelope(response),
          'authorization init',
        )
      }
      throw new Error(
        'response vault: authorization init response is invalid',
      )
    }
  }
}
