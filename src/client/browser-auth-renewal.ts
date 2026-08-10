import { getTokenExpiry } from '../claims/claims'
import {
  createDPoPKeyManager,
  type DPoPKeyManager,
} from '../dpop/dpop'
import {
  persistedLogoutGeneration,
  type CredentialGenerationSnapshot,
} from '../oidc/credential-generation'
import {
  authorizationState,
  readAuthorizationCodeResponseState,
  requireAuthorizationCodeCallback,
  type AuthorizationCodeCallback,
} from '../oidc/oidc'
import {
  OrdinaryAuthorizationPendingError,
  type OrdinaryAuthorizationCallbackCustody,
} from '../oidc/ordinary-authorization'
import {
  assertOrdinaryAuthorizationDPoPBinding,
  compensateOrdinaryAuthorizationCode,
  exchangeOrdinaryAuthorizationCode,
} from '../oidc/ordinary-authorization-exchange'
import {
  DEFAULT_SILENT_RENEW_RETRY_COUNT,
  generateAuthorizationNonce,
  refreshTokenGrant,
  silentAuthorizeURL,
  type SilentAuthorizationResponse,
  type TokenResponse,
} from '../oidc/silent-renew'
import {
  OAuthProtocolError,
  RecoveryAction,
  classifyRenewalError,
} from '../oidc/token-recovery'
import type { BroadcastMessage } from '../token/token-broadcast'
import type {
  ApplyTokenOptions,
  BrowserAuthRenewalOperations,
  BrowserAuthRuntime,
  SilentCredentialGrant,
} from './browser-auth-context'
import {
  RENEW_WINDOW_MS,
  StaleCredentialTransactionError,
} from './browser-auth-support'

function authorizationResponseURL(
  redirectUri: string,
  response: SilentAuthorizationResponse,
): string {
  const target = new URL(redirectUri)
  target.searchParams.set('state', response.state)
  if (response.code) target.searchParams.set('code', response.code)
  if (response.error) target.searchParams.set('error', response.error)
  return target.href
}

export function createBrowserAuthRenewalOperations(
  runtime: BrowserAuthRuntime,
): BrowserAuthRenewalOperations {
  async function renewViaIframe(
    organizationId: string | undefined,
    expectedGeneration: CredentialGenerationSnapshot,
    requireLiveAuthority = false,
  ): Promise<SilentCredentialGrant> {
    const assertExpectedAuthority = () => {
      if (requireLiveAuthority) {
        runtime.sessionOps.assertLiveCredentialAuthority(
          expectedGeneration,
        )
      } else {
        runtime.sessionOps.assertCredentialAuthority(
          expectedGeneration,
        )
      }
    }
    assertExpectedAuthority()
    if (runtime.responseVault) {
      const responseVaultGrant =
        await runtime.responseVault.authorizeInIframe(
          {
            prompt: 'none',
            organizationId,
          },
          expectedGeneration,
        )
      assertExpectedAuthority()
      return {
        tokens: responseVaultGrant.tokens,
        nonce: responseVaultGrant.nonce,
        dpopKey: responseVaultGrant.dpopKey,
        responseVaultGrant,
      }
    }

    const extraQueryParams: Record<string, string> = {}
    if (runtime.audience) {
      extraQueryParams.audience = runtime.audience
    }
    if (organizationId) {
      extraQueryParams.atol_org_id = organizationId
    }
    if (runtime.deriveEncryptionKey) {
      extraQueryParams.derive_encryption_key = 'true'
    }
    const start = {
      intent: {
        responseMode: 'web_message' as const,
        prompt: 'none',
        extraQueryParams,
        dpopEnabled: runtime.useDPoP,
        dpopRequired: runtime.requireDPoP,
      },
      credentialGeneration: expectedGeneration,
      nonce: generateAuthorizationNonce(),
      state: authorizationState(undefined, expectedGeneration),
      createDPoPKey: createDPoPKeyManager,
    }

    let lastError: unknown
    let callbackGrant:
      | {
          callback: AuthorizationCodeCallback
          custody: OrdinaryAuthorizationCallbackCustody
          dpopKey: DPoPKeyManager | null
        }
      | undefined
    for (
      let attempt = 0;
      attempt < DEFAULT_SILENT_RENEW_RETRY_COUNT;
      attempt++
    ) {
      try {
        const recovered =
          await runtime.ordinaryAuthorization!.claimPendingCallback(
            expectedGeneration,
          )
        let callback: AuthorizationCodeCallback
        let custody: OrdinaryAuthorizationCallbackCustody
        if (recovered) {
          callback = recovered.callback
          custody = recovered.custody
        } else {
          let authorizeUrl: string | undefined
          await runtime.ordinaryAuthorization!.begin(start, (url) => {
            if (authorizeUrl !== undefined) {
              throw new Error(
                'ordinary silent authorization navigated more than once',
              )
            }
            authorizeUrl = url
          })
          if (!authorizeUrl) {
            throw new Error(
              'ordinary silent authorization did not produce a navigation',
            )
          }
          assertExpectedAuthority()
          const response = await silentAuthorizeURL({
            authority: runtime.issuer,
            clientId: runtime.clientId,
            admittedAuthorizationUrl: authorizeUrl,
          })
          assertExpectedAuthority()
          const callbackState =
            await readAuthorizationCodeResponseState(
              runtime.manager,
              authorizationResponseURL(
                runtime.redirectUri,
                response,
              ),
            )
          custody =
            await runtime.ordinaryAuthorization!.claimCallback(
              callbackState,
              expectedGeneration,
            )
          try {
            callback = requireAuthorizationCodeCallback(callbackState)
          } catch (error) {
            if (callbackState.error) await custody.discard()
            else await custody.release()
            throw error
          }
        }
        let dpopKey: DPoPKeyManager | null
        try {
          dpopKey =
            assertOrdinaryAuthorizationDPoPBinding(
              runtime.ordinaryExchangeBinding,
              custody,
            )
        } catch (error) {
          await custody.release()
          throw error
        }
        callbackGrant = { callback, custody, dpopKey }
        break
      } catch (error) {
        lastError = error
        if (
          !(error instanceof OrdinaryAuthorizationPendingError) &&
          classifyRenewalError(error) !== RecoveryAction.Retry
        ) {
          throw error
        }
        if (attempt < DEFAULT_SILENT_RENEW_RETRY_COUNT - 1) {
          await new Promise((resolve) =>
            setTimeout(resolve, 200 * 2 ** attempt),
          )
        }
      }
    }
    if (!callbackGrant) {
      throw lastError instanceof Error
        ? lastError
        : new Error('ordinary silent authorization failed after retries')
    }
    const { callback, custody, dpopKey } = callbackGrant
    if (custody.compensationRequired) {
      await compensateOrdinaryAuthorizationCode(
        runtime.ordinaryExchangeBinding,
        custody,
        callback,
        dpopKey,
      )
      throw new Error(
        'ordinary silent authorization compensation completed',
      )
    }
    let tokens: TokenResponse
    try {
      tokens = await exchangeOrdinaryAuthorizationCode(
        runtime.ordinaryExchangeBinding,
        callback,
        dpopKey,
      )
    } catch (error) {
      if (
        error instanceof OAuthProtocolError &&
        error.code === 'invalid_grant'
      ) {
        await custody.discard()
        throw error
      }
      await custody.release()
      throw new OrdinaryAuthorizationPendingError()
    }
    assertExpectedAuthority()
    try {
      await custody.markCodeIssued()
    } catch {
      throw new OrdinaryAuthorizationPendingError()
    }
    return {
      tokens,
      nonce: callback.nonce,
      dpopKey,
      ordinaryAuthorizationGrant: {
        complete: () => custody.complete(),
        compensate: () =>
          compensateOrdinaryAuthorizationCode(
            runtime.ordinaryExchangeBinding,
            custody,
            callback,
            dpopKey,
          ),
      },
    }
  }

  async function renewOnce(
    force: boolean,
    startEpoch: number,
    publishSignal: boolean,
    renewalGeneration: CredentialGenerationSnapshot,
  ): Promise<string | undefined> {
    await runtime.credentialMutationTail
    if (startEpoch !== runtime.credentialEpoch) {
      return runtime.accessToken
    }
    try {
      runtime.sessionOps.assertLiveCredentialAuthority(
        renewalGeneration,
      )
    } catch (error) {
      if (error instanceof StaleCredentialTransactionError) {
        return runtime.accessToken
      }
      throw error
    }
    const startingAccessToken = runtime.accessToken
    const startingRefreshToken = runtime.refreshToken
    const startingOrganizationId = runtime.currentOrganizationId

    if (!force && startingAccessToken) {
      const exp = getTokenExpiry(startingAccessToken)
      if (
        exp !== null &&
        Date.now() < exp - RENEW_WINDOW_MS
      ) {
        return startingAccessToken
      }
    }

    try {
      let tokens: TokenResponse
      let expectedNonce: string | undefined
      let replacementDPoP: DPoPKeyManager | null | undefined
      let authorizationGrant: SilentCredentialGrant | undefined
      if (runtime.useRefreshTokens && startingRefreshToken) {
        try {
          runtime.sessionOps.assertLiveCredentialAuthority(
            renewalGeneration,
          )
          tokens = await refreshTokenGrant(
            runtime.issuer,
            runtime.clientId,
            startingRefreshToken,
            runtime.scope,
            runtime.audience,
            runtime.dpop ?? undefined,
          )
          runtime.sessionOps.assertLiveCredentialAuthority(
            renewalGeneration,
          )
        } catch (grantError) {
          if (
            !runtime.useRefreshTokensFallback ||
            classifyRenewalError(grantError) !==
              RecoveryAction.Retry
          ) {
            throw grantError
          }
          const grant = await renewViaIframe(
            startingOrganizationId,
            renewalGeneration,
            true,
          )
          authorizationGrant = grant
          tokens = grant.tokens
          expectedNonce = grant.nonce
          replacementDPoP = grant.dpopKey
        }
      } else {
        const grant = await renewViaIframe(
          startingOrganizationId,
          renewalGeneration,
          true,
        )
        authorizationGrant = grant
        tokens = grant.tokens
        expectedNonce = grant.nonce
        replacementDPoP = grant.dpopKey
      }

      if (
        startEpoch !== runtime.credentialEpoch &&
        !authorizationGrant
      ) {
        return runtime.accessToken
      }
      const applyOptions: ApplyTokenOptions = {
        epoch: startEpoch,
        expectedOrganizationId: startingOrganizationId,
        enforceExpectedOrganization: true,
        preserveExistingTokens: true,
        expectedNonce,
        dpopKey: replacementDPoP,
        replaceDPoPKey: replacementDPoP !== undefined,
        credentialGeneration: renewalGeneration,
        requireLiveCredentialAuthority: true,
      }
      if (authorizationGrant) {
        await runtime.credentialOps.applyAuthorizationGrant(
          authorizationGrant,
          applyOptions,
        )
      } else {
        await runtime.credentialOps.applyTokens(
          tokens,
          applyOptions,
        )
      }
      runtime.sessionOps.assertLiveCredentialAuthority(
        renewalGeneration,
      )

      if (publishSignal && runtime.broadcast) {
        runtime.broadcast.publish({
          type: 'credentials-invalidated',
          sentAt: Date.now(),
        })
      }
      runtime.renewBackoff = 0
      return tokens.access_token
    } catch (error) {
      if (
        error instanceof StaleCredentialTransactionError ||
        startEpoch !== runtime.credentialEpoch
      ) {
        return runtime.accessToken
      }
      switch (classifyRenewalError(error)) {
        case RecoveryAction.ForceReauth: {
          const invalidation =
            runtime.sessionOps.invalidateAuthorizationAuthority(true)
          runtime.sessionOps.clearSession()
          if (
            publishSignal &&
            runtime.broadcast &&
            invalidation.logoutGeneration
          ) {
            runtime.broadcast.publish({
              type: 'session-ended',
              logoutGeneration: invalidation.logoutGeneration,
              sentAt: Date.now(),
            })
          }
          await invalidation.completion
          return undefined
        }
        case RecoveryAction.Retry:
          runtime.renewBackoff = Math.min(
            10,
            runtime.renewBackoff + 1,
          )
          throw error
        case RecoveryAction.Surface:
        default:
          throw error
      }
    }
  }

  function renewSingleFlight(
    force: boolean,
    publishSignal: boolean,
  ): Promise<string | undefined> {
    if (!runtime.accessToken) return Promise.resolve(undefined)
    let renewalGeneration: CredentialGenerationSnapshot
    try {
      renewalGeneration =
        runtime.sessionOps.requireLiveCredentialGeneration()
    } catch (error) {
      if (error instanceof StaleCredentialTransactionError) {
        return Promise.resolve(undefined)
      }
      return Promise.reject(error)
    }
    const epoch = runtime.credentialEpoch
    if (runtime.renewInFlight?.epoch === epoch) {
      return runtime.renewInFlight.promise
    }
    const promise = renewOnce(
      force,
      epoch,
      publishSignal,
      renewalGeneration,
    ).finally(() => {
      if (runtime.renewInFlight?.promise === promise) {
        runtime.renewInFlight = null
      }
    })
    runtime.renewInFlight = { epoch, promise }
    return promise
  }

  async function getToken(): Promise<string | undefined> {
    if (!runtime.accessToken) return undefined
    runtime.sessionOps.assertLiveCredentialAuthority()
    const exp = getTokenExpiry(runtime.accessToken)
    if (
      exp !== null &&
      Date.now() < exp - RENEW_WINDOW_MS
    ) {
      return runtime.accessToken
    }
    return renewSingleFlight(false, true)
  }

  async function onBroadcast(
    message: BroadcastMessage,
  ): Promise<void> {
    if (message.type === 'session-ended') {
      const active = runtime.activeCredentialGeneration
      if (!active) return
      let persisted: string | null
      try {
        persisted = persistedLogoutGeneration(
          runtime.credentialGenerationBinding,
        )
      } catch {
        void runtime.sessionOps.clearSession()
        return
      }
      if (persisted === null) {
        void runtime.sessionOps.clearSession()
        return
      }
      if (
        message.logoutGeneration !== persisted ||
        message.logoutGeneration === active.logout
      ) {
        return
      }
      void runtime.sessionOps.clearSession()
      return
    }
    if (!runtime.currentUser) return
    await renewSingleFlight(true, false).catch(() => undefined)
  }

  async function forceRenew(): Promise<string | undefined> {
    return renewSingleFlight(true, true)
  }

  return {
    renewViaIframe,
    renewSingleFlight,
    getToken,
    forceRenew,
    onBroadcast,
  }
}
