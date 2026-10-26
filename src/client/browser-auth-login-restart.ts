import {
  credentialGenerationSnapshot,
  currentCredentialAuthority,
  rotateLogoutGeneration,
  type CredentialGenerationSnapshot,
} from '../oidc/credential-generation'
import {
  restartResponseVaultFailedInitialization,
} from '../oidc/response-vault-login-cancellation'
import { normalizeSameOriginReturnTo } from '../oidc/return-to'
import type { BeginLoginOptions } from './browser-auth'
import type { BrowserAuthRuntime } from './browser-auth-context'

export function createBrowserAuthLoginRestart(
  runtime: BrowserAuthRuntime,
  beginLoginOnce: (
    options?: BeginLoginOptions,
    precedingLogout?: Promise<void> | null,
    onGeneration?: (generation: CredentialGenerationSnapshot) => void,
  ) => Promise<void>,
) {
  function canRestartLogin(): boolean {
    return (
      runtime.responseVault !== null &&
      runtime.initPromise !== null &&
      runtime.initRejected &&
      runtime.failedInitCancellationAuthority !== null &&
      !runtime.lifecycleOps.isCallbackUrl() &&
      !runtime.lifecycleOps.isPostLogoutCallbackUrl() &&
      runtime.completeLoginPromise === null &&
      runtime.currentUser === null &&
      runtime.accessToken === undefined &&
      runtime.currentIdToken === undefined &&
      runtime.refreshToken === undefined &&
      !runtime.destroyed
    )
  }

  async function restartLoginOnce(
    options?: BeginLoginOptions,
  ): Promise<void> {
    normalizeSameOriginReturnTo(
      options?.returnTo,
      runtime.redirectUri,
    )
    const authority = runtime.failedInitCancellationAuthority
    if (!canRestartLogin() || authority === null) {
      throw new Error(
        'restartLogin requires a rejected signed-out response-vault initialization',
      )
    }
    if (runtime.destroyed) {
      throw new Error('auth client has been destroyed')
    }

    let restartInvalidation = runtime.failedInitRestartInvalidation
    if (restartInvalidation === null) {
      const current = currentCredentialAuthority(
        runtime.credentialGenerationBinding,
      )
      if (current.generation !== authority.credentialGeneration.logout) {
        throw new Error(
          'restartLogin could not invalidate the abandoned authorization',
        )
      }
      const logoutGeneration = rotateLogoutGeneration(
        runtime.credentialGenerationBinding,
      )
      restartInvalidation = {
        referenceId: authority.reference.id,
        logoutGeneration,
        published: false,
        settled: false,
      }
      runtime.failedInitRestartInvalidation = restartInvalidation
    }
    if (!restartInvalidation.settled) {
      const current = currentCredentialAuthority(
        runtime.credentialGenerationBinding,
      )
      if (
        restartInvalidation.referenceId !== authority.reference.id ||
        !current.signedOut ||
        current.generation !== restartInvalidation.logoutGeneration ||
        current.generation === authority.credentialGeneration.logout
      ) {
        throw new Error(
          'restartLogin could not invalidate the abandoned authorization',
        )
      }
      if (!restartInvalidation.published) {
        runtime.broadcast?.publish({
          type: 'session-ended',
          logoutGeneration: restartInvalidation.logoutGeneration,
          sentAt: Date.now(),
        })
        restartInvalidation = {
          ...restartInvalidation,
          published: true,
        }
        runtime.failedInitRestartInvalidation = restartInvalidation
      }
      const confirmed = currentCredentialAuthority(
        runtime.credentialGenerationBinding,
      )
      if (
        !confirmed.signedOut ||
        confirmed.generation !== restartInvalidation.logoutGeneration
      ) {
        throw new Error(
          'restartLogin could not invalidate the abandoned authorization',
        )
      }
      await runtime.sessionOps.clearSession()

      await restartResponseVaultFailedInitialization(
        runtime.responseVault as NonNullable<
          typeof runtime.responseVault
        >,
        authority as NonNullable<typeof authority>,
        restartInvalidation.logoutGeneration,
        () => {
          runtime.destroyAuthorizationCleanupStarted = true
        },
      )
      restartInvalidation = {
        ...restartInvalidation,
        settled: true,
      }
      runtime.failedInitRestartInvalidation = restartInvalidation
    }
    const activeRestartInvalidation = restartInvalidation
    const restartAuthorizationGeneration =
      activeRestartInvalidation.authorizationGeneration
    const current = currentCredentialAuthority(
      runtime.credentialGenerationBinding,
    )
    if (restartAuthorizationGeneration === undefined) {
      if (
        !current.signedOut ||
        current.generation !== activeRestartInvalidation.logoutGeneration
      ) {
        throw new Error(
          'restartLogin could not preserve restart authority',
        )
      }
    } else {
      const currentGeneration = credentialGenerationSnapshot(
        runtime.credentialGenerationBinding,
      )
      if (
        current.signedOut ||
        current.generation !== restartAuthorizationGeneration.logout ||
        currentGeneration.tabOwner !==
          restartAuthorizationGeneration.tabOwner
      ) {
        throw new Error(
          'restartLogin could not preserve restart authority',
        )
      }
    }
    await beginLoginOnce(options, null, (generation) => {
      if (
        activeRestartInvalidation.authorizationGeneration !== undefined
      ) {
        if (
          activeRestartInvalidation.authorizationGeneration.logout !==
            generation.logout ||
          activeRestartInvalidation.authorizationGeneration.tabOwner !==
            generation.tabOwner
        ) {
          throw new Error(
            'restartLogin could not preserve restart authority',
          )
        }
        return
      }
      restartInvalidation = {
        ...activeRestartInvalidation,
        authorizationGeneration: Object.freeze({ ...generation }),
      }
      runtime.failedInitRestartInvalidation = restartInvalidation
    })
    runtime.initPromise = null
    runtime.initRejected = false
    runtime.failedInitCancellationAuthority = null
    runtime.failedInitRestartInvalidation = null
  }

  function restartLogin(
    options?: BeginLoginOptions,
  ): Promise<void> {
    if (runtime.restartLoginInFlight) {
      return runtime.restartLoginInFlight
    }
    if (runtime.cancelLoginInFlight) {
      return Promise.reject(
        new Error(
          'restartLogin is unavailable while login cancellation is in progress',
        ),
      )
    }
    if (runtime.logoutInFlight) {
      return Promise.reject(
        new Error(
          'restartLogin is unavailable while logout is in progress',
        ),
      )
    }
    const operation = runtime.enqueueAuthorizationAction(() =>
      restartLoginOnce(options),
    )
    runtime.restartLoginInFlight = operation
    const clearFlight = () => {
      if (runtime.restartLoginInFlight === operation) {
        runtime.restartLoginInFlight = null
      }
    }
    void operation.then(clearFlight, clearFlight)
    return operation
  }

  return { canRestartLogin, restartLogin }
}
