import type { User } from 'oidc-client-ts'
import { extractKEKFromFragment } from '../crypto/encryption'
import { createDPoPKeyManager } from '../dpop/dpop'
import {
  currentCredentialAuthority,
  credentialGenerationSnapshot,
  type CredentialGenerationSnapshot,
} from '../oidc/credential-generation'
import {
  getAccessToken,
  getIdToken,
} from '../oidc/oidc'
import { settleRecoveredOrdinaryAuthorization } from '../oidc/ordinary-authorization-exchange'
import {
  LoginRequiredError,
} from '../oidc/silent-renew'
import {
  takeResponseVaultFailedInitializationAuthority,
} from '../oidc/response-vault-failed-initialization'
import { createTokenBroadcast } from '../token/token-broadcast'
import type {
  BrowserAuthLifecycleOperations,
  BrowserAuthRuntime,
} from './browser-auth-context'
import {
  StaleCredentialTransactionError,
  signoutStateGeneration,
  warnIfSeedTokenNotFresh,
} from './browser-auth-support'

export function createBrowserAuthLifecycleOperations(
  runtime: BrowserAuthRuntime,
): BrowserAuthLifecycleOperations {
  function isCallbackUrl(): boolean {
    if (typeof window === 'undefined') return false
    if (runtime.responseVault) {
      return runtime.responseVault.isCleanCallback()
    }
    const params = new URLSearchParams(window.location.search)
    return params.has('code') || params.has('error')
  }

  function isPostLogoutCallbackUrl(): boolean {
    if (typeof window === 'undefined') return false
    const current = new URL(window.location.href)
    const expected = new URL(runtime.postLogoutRedirectUri)
    return (
      current.origin === expected.origin &&
      current.pathname === expected.pathname &&
      current.hash === '' &&
      current.searchParams.has('state') &&
      !current.searchParams.has('code')
    )
  }

  async function consumePostLogoutCallback(
    expectedLogoutGeneration: string,
  ): Promise<void> {
    if (!isPostLogoutCallbackUrl()) return
    try {
      const response =
        await runtime.manager.signoutRedirectCallback(
          window.location.href,
        )
      if (
        signoutStateGeneration(response.userState) !==
        expectedLogoutGeneration
      ) {
        throw new Error(
          'OIDC post-logout callback was superseded',
        )
      }
    } finally {
      const clean = new URL(runtime.postLogoutRedirectUri)
      window.history.replaceState(
        {},
        document.title,
        `${clean.pathname}${clean.search}${clean.hash}`,
      )
    }
  }

  async function settleSignedOutStartup(
    expectedLogoutGeneration: string,
  ): Promise<boolean> {
    const current = currentCredentialAuthority(
      runtime.credentialGenerationBinding,
    )
    if (
      !current.signedOut ||
      current.generation !== expectedLogoutGeneration
    ) {
      return false
    }

    let firstError: unknown
    if (runtime.responseVault) {
      try {
        await runtime.responseVault.invalidateSignedOutLifecycle()
      } catch (error) {
        firstError = error
      }
    }
    if (runtime.ordinaryAuthorization) {
      try {
        await runtime.ordinaryAuthorization.invalidateSignedOutLifecycle()
      } catch (error) {
        firstError ??= error
      }
    }
    try {
      await runtime.sessionOps.clearSession()
    } catch (error) {
      firstError ??= error
    }
    try {
      await consumePostLogoutCallback(expectedLogoutGeneration)
    } catch (error) {
      firstError ??= error
    }
    if (firstError !== undefined) throw firstError
    return true
  }

  function ensureRuntimeInitialized(): Promise<void> {
    if (runtime.runtimeInitPromise) {
      return runtime.runtimeInitPromise
    }
    runtime.runtimeInitPromise = (async () => {
      if (runtime.destroyed) {
        throw new Error('auth client has been destroyed')
      }
      if (runtime.deriveEncryptionKey) {
        runtime.fragmentKEK = extractKEKFromFragment()
      }
      if (runtime.useDPoP && !runtime.responseVault) {
        const initializedDPoP = await createDPoPKeyManager()
        if (runtime.destroyed) {
          throw new Error('auth client has been destroyed')
        }
        runtime.dpop = initializedDPoP
        if (!initializedDPoP && runtime.requireDPoP) {
          throw new Error(
            'DPoP is required but WebCrypto could not create a key',
          )
        }
      }
      if (runtime.destroyed) {
        throw new Error('auth client has been destroyed')
      }
      runtime.broadcast = createTokenBroadcast(
        `atol:tokens:${runtime.issuer}:${runtime.clientId}`,
      )
      runtime.broadcast.subscribe((message) => {
        void runtime.renewalOps.onBroadcast(message)
      })
    })()
    return runtime.runtimeInitPromise
  }

  async function adoptOidcUser(
    oidcUser: User,
    epoch: number,
    generation: CredentialGenerationSnapshot,
  ): Promise<void> {
    const storedAccessToken = getAccessToken(oidcUser)
    if (!storedAccessToken) {
      throw new Error('stored OIDC user has no access token')
    }
    await runtime.credentialOps.applyTokens(
      {
        access_token: storedAccessToken,
        id_token: getIdToken(oidcUser),
        refresh_token: oidcUser.refresh_token,
        token_type: oidcUser.token_type,
        expires_in: oidcUser.expires_in ?? 0,
        scope: oidcUser.scope,
      },
      { epoch, credentialGeneration: generation },
    )
  }

  async function settleOrdinaryCallbackBeforeRestore(
    generation: CredentialGenerationSnapshot,
  ): Promise<void> {
    if (!runtime.ordinaryAuthorization) return
    const recovery =
      await runtime.ordinaryAuthorization.claimPendingCallback(
        generation,
      )
    if (!recovery) return
    try {
      await runtime.enqueueUserStore(() =>
        runtime.manager.removeUser(),
      )
    } catch (error) {
      await recovery.custody.release()
      throw error
    }
    await settleRecoveredOrdinaryAuthorization(
      runtime.ordinaryExchangeBinding,
      recovery,
    )
  }

  async function restoreSession(): Promise<void> {
    const restoreAuthority = currentCredentialAuthority(
      runtime.credentialGenerationBinding,
    )
    if (restoreAuthority.signedOut) {
      await settleSignedOutStartup(restoreAuthority.generation)
      return
    }
    const restoreEpoch = runtime.credentialEpoch
    const restoreGeneration = credentialGenerationSnapshot(
      runtime.credentialGenerationBinding,
    )
    if (restoreGeneration.logout !== restoreAuthority.generation) {
      const changed = currentCredentialAuthority(
        runtime.credentialGenerationBinding,
      )
      if (changed.signedOut) {
        await settleSignedOutStartup(changed.generation)
        return
      }
      throw new StaleCredentialTransactionError()
    }
    await settleOrdinaryCallbackBeforeRestore(restoreGeneration)
    runtime.sessionOps.assertCredentialAuthority(restoreGeneration)
    if (restoreEpoch !== runtime.credentialEpoch) return
    let oidcUser: User | null = await runtime.manager.getUser()
    runtime.sessionOps.assertCredentialAuthority(restoreGeneration)
    if (restoreEpoch !== runtime.credentialEpoch) return
    if (oidcUser?.expired) oidcUser = null
    if (!oidcUser) {
      try {
        if (!runtime.restoreInFlight) {
          runtime.restoreInFlight =
            runtime.renewalOps.renewViaIframe(
              undefined,
              restoreGeneration,
            )
        }
        const grant = await runtime.restoreInFlight
        await runtime.credentialOps.applyAuthorizationGrant(grant, {
          epoch: restoreEpoch,
          expectedNonce: grant.nonce,
          dpopKey: grant.dpopKey,
          replaceDPoPKey: true,
          credentialGeneration: restoreGeneration,
        })
        return
      } catch (error) {
        if (
          error instanceof StaleCredentialTransactionError ||
          restoreEpoch !== runtime.credentialEpoch
        ) {
          return
        }
        if (error instanceof LoginRequiredError) {
          oidcUser = null
        } else {
          throw error
        }
      } finally {
        runtime.restoreInFlight = null
      }
    }
    if (oidcUser) {
      await adoptOidcUser(
        oidcUser,
        restoreEpoch,
        restoreGeneration,
      )
    } else {
      runtime.sessionOps.emit()
    }
  }

  async function init() {
    if (runtime.destroyed) {
      throw new Error('auth client has been destroyed')
    }
    if (runtime.initPromise) {
      await runtime.initPromise
      if (runtime.destroyed) {
        throw new Error('auth client has been destroyed')
      }
      return runtime.sessionOps.session()
    }
    const initialization = (async () => {
      await ensureRuntimeInitialized()
      const startupAuthority = currentCredentialAuthority(
        runtime.credentialGenerationBinding,
      )
      if (
        startupAuthority.signedOut &&
        !runtime.responseVault &&
        isCallbackUrl() &&
        !isPostLogoutCallbackUrl()
      ) {
        await runtime.callbackOps.completeLogin()
        return runtime.sessionOps.session()
      }
      if (
        startupAuthority.signedOut &&
        (await settleSignedOutStartup(startupAuthority.generation))
      ) {
        return runtime.sessionOps.session()
      }
      if (isPostLogoutCallbackUrl()) {
        throw new Error(
          'OIDC post-logout callback is not current',
        )
      }
      if (runtime.initialTestSession) {
        warnIfSeedTokenNotFresh(
          runtime.initialTestSession.access_token,
        )
        await runtime.credentialOps.applyTokens(
          runtime.initialTestSession,
          {
            testSession: true,
            credentialGeneration: credentialGenerationSnapshot(
              runtime.credentialGenerationBinding,
            ),
          },
        )
        return runtime.sessionOps.session()
      }
      if (
        runtime.responseVault &&
        isCallbackUrl() &&
        runtime.responseVault.isOwnedIframeCallback()
      ) {
        runtime.sessionOps.emit()
        return runtime.sessionOps.session()
      }
      if (isCallbackUrl()) {
        await runtime.callbackOps.completeLogin()
      } else {
        await restoreSession()
      }
      return runtime.sessionOps.session()
    })()
    runtime.initPromise = initialization
    try {
      return await initialization
    } catch (error) {
      if (runtime.initPromise === initialization) {
        runtime.initRejected = true
        runtime.failedInitCancellationAuthority =
          runtime.responseVault === null
            ? null
            : takeResponseVaultFailedInitializationAuthority(error) ?? null
        runtime.failedInitRestartInvalidation = null
      }
      throw error
    }
  }

  return {
    isCallbackUrl,
    isPostLogoutCallbackUrl,
    settleSignedOutStartup,
    ensureRuntimeInitialized,
    restoreSession,
    init,
  }
}
