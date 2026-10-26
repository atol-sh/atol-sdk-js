import type { DPoPProofResult } from '../claims/types'
import { createDPoPKeyManager } from '../dpop/dpop'
import {
  credentialGenerationForLogin,
  credentialGenerationSnapshot,
  currentCredentialAuthority,
  type CredentialGenerationSnapshot,
} from '../oidc/credential-generation'
import {
  cancelResponseVaultFailedInitialization,
} from '../oidc/response-vault-login-cancellation'
import {
  authorizationState,
} from '../oidc/oidc'
import { normalizeSameOriginReturnTo } from '../oidc/return-to'
import {
  generateAuthorizationNonce,
  revokeToken,
  type TokenResponse,
} from '../oidc/silent-renew'
import type {
  AtolBrowserAuth,
  AtolSession,
  BeginLoginOptions,
  GetAccessTokenOptions,
  StepUpOptions,
} from './browser-auth'
import type { BrowserAuthRuntime } from './browser-auth-context'
import { createBrowserAuthLoginRestart } from './browser-auth-login-restart'
import { AtolBrowserAuthCleanupError } from './browser-auth-diagnostics'
import {
  CANONICAL_ULID,
  StaleCredentialTransactionError,
  signoutState,
  warnIfSeedTokenNotFresh,
} from './browser-auth-support'

export function createBrowserAuthActions(
  runtime: BrowserAuthRuntime,
): AtolBrowserAuth {
  async function beginLoginOnce(
    options?: BeginLoginOptions,
    precedingLogout?: Promise<void> | null,
    onGeneration?: (
      generation: CredentialGenerationSnapshot,
    ) => void,
  ): Promise<void> {
    const returnTo = normalizeSameOriginReturnTo(
      options?.returnTo,
      runtime.redirectUri,
    )
    if (precedingLogout) await precedingLogout
    const authorizationGeneration = credentialGenerationForLogin(
      runtime.credentialGenerationBinding,
    )
    onGeneration?.(authorizationGeneration)
    const authorizationEpoch = runtime.credentialEpoch
    await runtime.credentialMutationTail
    await runtime.lifecycleOps.ensureRuntimeInitialized()
    if (
      runtime.destroyed ||
      authorizationEpoch !== runtime.credentialEpoch
    ) {
      throw new StaleCredentialTransactionError()
    }
    runtime.sessionOps.assertCredentialAuthority(
      authorizationGeneration,
    )
    if (runtime.responseVault) {
      await runtime.responseVault.beginInteractive(
        {
          prompt: options?.prompt,
          maxAge: options?.maxAge,
          acrValues: options?.acrValues,
          returnTo,
        },
        authorizationGeneration,
      )
      runtime.destroyAuthorizationCleanupStarted = false
      return
    }
    const extraQueryParams: Record<string, string> = {}
    if (runtime.audience) {
      extraQueryParams.audience = runtime.audience
    }
    if (runtime.deriveEncryptionKey) {
      extraQueryParams.derive_encryption_key = 'true'
    }
    if (
      runtime.destroyed ||
      authorizationEpoch !== runtime.credentialEpoch
    ) {
      throw new StaleCredentialTransactionError()
    }
    runtime.sessionOps.assertCredentialAuthority(
      authorizationGeneration,
    )
    await runtime.ordinaryAuthorization!.begin({
      intent: {
        prompt: options?.prompt,
        maxAge: options?.maxAge,
        acrValues: options?.acrValues,
        returnTo,
        extraQueryParams,
        dpopEnabled: runtime.useDPoP,
        dpopRequired: runtime.requireDPoP,
      },
      credentialGeneration: authorizationGeneration,
      nonce: generateAuthorizationNonce(),
      state: authorizationState(
        returnTo,
        authorizationGeneration,
      ),
      createDPoPKey: createDPoPKeyManager,
    })
  }

  function beginLogin(
    options?: BeginLoginOptions,
  ): Promise<void> {
    if (runtime.restartLoginInFlight) {
      return runtime.restartLoginInFlight
    }
    const cancellation = runtime.cancelLoginInFlight
    const logout = runtime.logoutInFlight
    return runtime.enqueueAuthorizationAction(async () => {
      if (cancellation) await cancellation
      await beginLoginOnce(options, logout)
    })
  }

  async function stepUp(options?: StepUpOptions): Promise<void> {
    await beginLogin({
      prompt: 'login',
      maxAge: options?.maxAge ?? 0,
      acrValues: options?.acrValues ?? 'mfa',
      returnTo: options?.returnTo,
    })
  }

  async function selectOrganization(
    organizationId: string,
  ): Promise<AtolSession> {
    if (!CANONICAL_ULID.test(organizationId)) {
      throw new Error(
        'organizationId must be a canonical ULID',
      )
    }
    if (!runtime.currentUser) {
      throw new Error(
        'cannot select an organization without an authenticated session',
      )
    }
    const selectionGeneration =
      runtime.sessionOps.requireLiveCredentialGeneration()
    await runtime.credentialMutationTail
    runtime.sessionOps.assertLiveCredentialAuthority(
      selectionGeneration,
    )
    if (!runtime.currentUser) {
      throw new StaleCredentialTransactionError()
    }

    const selectionEpoch = ++runtime.credentialEpoch
    runtime.sessionOps.clearRenewTimer()
    try {
      const grant = await runtime.renewalOps.renewViaIframe(
        organizationId,
        selectionGeneration,
        true,
      )
      await runtime.credentialOps.applyAuthorizationGrant(grant, {
        epoch: selectionEpoch,
        expectedOrganizationId: organizationId,
        enforceExpectedOrganization: true,
        preserveExistingTokens: false,
        expectedNonce: grant.nonce,
        dpopKey: grant.dpopKey,
        replaceDPoPKey: true,
        advanceEpochOnCommit: true,
        credentialGeneration: selectionGeneration,
        requireLiveCredentialAuthority: true,
      })
      runtime.sessionOps.assertLiveCredentialAuthority(
        selectionGeneration,
      )
      runtime.broadcast?.publish({
        type: 'credentials-invalidated',
        sentAt: Date.now(),
      })
      return runtime.sessionOps.session()
    } catch (error) {
      if (selectionEpoch === runtime.credentialEpoch) {
        runtime.sessionOps.scheduleRenew()
      }
      throw error
    }
  }

  async function logoutOnce(): Promise<void> {
    if (runtime.cancelLoginInFlight) {
      await runtime.cancelLoginInFlight
    }
    runtime.pendingLogoutRefreshToken ??= runtime.refreshToken
    runtime.pendingLogoutIdToken ??= runtime.currentIdToken
    const invalidation =
      runtime.sessionOps.invalidateAuthorizationAuthority(true)
    const userStoreClear = runtime.sessionOps.clearSession()
    const vaultClear = runtime.deriveEncryptionKey
      ? runtime.enqueueCredentialMutation(() =>
          runtime.sessionOps.getVault().clear(),
        )
      : Promise.resolve()
    if (runtime.broadcast && invalidation.logoutGeneration) {
      runtime.broadcast.publish({
        type: 'session-ended',
        logoutGeneration: invalidation.logoutGeneration,
        sentAt: Date.now(),
      })
    }
    let firstError: unknown
    if (runtime.pendingLogoutRefreshToken) {
      try {
        await revokeToken(
          runtime.issuer,
          runtime.clientId,
          runtime.pendingLogoutRefreshToken,
        )
        runtime.pendingLogoutRefreshToken = undefined
      } catch (error) {
        firstError = error
      }
    }
    try {
      await userStoreClear
    } catch (error) {
      firstError ??= error
    }
    try {
      await invalidation.completion
    } catch (error) {
      firstError ??= error
    }
    try {
      await vaultClear
    } catch (error) {
      firstError ??= error
    }
    let ownsSignedOutAuthority = false
    if (invalidation.logoutGeneration) {
      try {
        const authority = currentCredentialAuthority(
          runtime.credentialGenerationBinding,
        )
        ownsSignedOutAuthority =
          authority.signedOut &&
          authority.generation ===
            invalidation.logoutGeneration
        if (!ownsSignedOutAuthority) {
          firstError ??= new Error('logout was superseded')
        }
      } catch (error) {
        firstError ??= error
      }
    }
    if (
      invalidation.logoutGeneration &&
      ownsSignedOutAuthority
    ) {
      try {
        await runtime.manager.signoutRedirect({
          post_logout_redirect_uri:
            runtime.postLogoutRedirectUri,
          ...(runtime.pendingLogoutIdToken
            ? { id_token_hint: runtime.pendingLogoutIdToken }
            : {}),
          state: signoutState(
            invalidation.logoutGeneration,
          ),
        })
      } catch (error) {
        firstError ??= error
      }
    } else if (!invalidation.logoutGeneration) {
      firstError ??= new Error(
        'logout could not persist signed-out authority',
      )
    }
    if (firstError !== undefined) throw firstError
    runtime.pendingLogoutIdToken = undefined
  }

  function logout(): Promise<void> {
    if (runtime.logoutInFlight) return runtime.logoutInFlight
    if (runtime.restartLoginInFlight) {
      return Promise.reject(
        new Error(
          'logout is unavailable while login restart is in progress',
        ),
      )
    }
    const operation = logoutOnce().finally(() => {
      if (runtime.logoutInFlight === operation) {
        runtime.logoutInFlight = null
      }
    })
    runtime.logoutInFlight = operation
    return operation
  }

  async function cancelLoginOnce(): Promise<void> {
    if (!runtime.responseVault) {
      throw new Error('cancelLogin requires response-vault authorization')
    }
    const recoverableFailedInitialization =
      runtime.initPromise !== null &&
      runtime.initRejected &&
      runtime.failedInitCancellationAuthority !== null &&
      !runtime.lifecycleOps.isCallbackUrl() &&
      !runtime.lifecycleOps.isPostLogoutCallbackUrl()
    if (
      (runtime.initPromise !== null &&
        !recoverableFailedInitialization) ||
      runtime.completeLoginPromise !== null ||
      runtime.currentUser !== null ||
      runtime.accessToken !== undefined ||
      runtime.currentIdToken !== undefined ||
      runtime.refreshToken !== undefined
    ) {
      throw new Error(
        'cancelLogin requires an uninitialized signed-out client',
      )
    }
    if (runtime.destroyed) {
      throw new Error('auth client has been destroyed')
    }
    const markCleanupOwned = () => {
      runtime.destroyAuthorizationCleanupStarted = true
    }
    if (recoverableFailedInitialization) {
      await cancelResponseVaultFailedInitialization(
        runtime.responseVault,
        runtime.failedInitCancellationAuthority as NonNullable<
          typeof runtime.failedInitCancellationAuthority
        >,
        markCleanupOwned,
      )
    } else {
      await runtime.responseVault.cancelLogin(markCleanupOwned)
    }
    if (recoverableFailedInitialization) {
      runtime.initPromise = null
      runtime.initRejected = false
      runtime.failedInitCancellationAuthority = null
    }
  }

  function cancelLogin(): Promise<void> {
    if (runtime.cancelLoginInFlight) return runtime.cancelLoginInFlight
    if (runtime.restartLoginInFlight) {
      return Promise.reject(
        new Error(
          'cancelLogin is unavailable while login restart is in progress',
        ),
      )
    }
    if (runtime.logoutInFlight) {
      return Promise.reject(
        new Error(
          'cancelLogin is unavailable while logout is in progress',
        ),
      )
    }
    const operation = runtime.enqueueAuthorizationAction(
      cancelLoginOnce,
    )
    runtime.cancelLoginInFlight = operation
    const clearFlight = () => {
      if (runtime.cancelLoginInFlight === operation) {
        runtime.cancelLoginInFlight = null
      }
    }
    void operation.then(clearFlight, clearFlight)
    return operation
  }

  async function getAccessTokenPublic(
    options?: GetAccessTokenOptions,
  ): Promise<
    { token: string; proof?: string } | undefined
  > {
    const token = await runtime.renewalOps.getToken()
    if (!token) return undefined
    const proofKey = runtime.dpop
    const proofEpoch = runtime.credentialEpoch
    if (options?.dpop && proofKey) {
      const proof = await proofKey.signProof(
        options.dpop.method,
        options.dpop.url,
        { accessToken: token },
      )
      if (
        runtime.destroyed ||
        proofEpoch !== runtime.credentialEpoch ||
        runtime.accessToken !== token ||
        runtime.dpop !== proofKey
      ) {
        throw new StaleCredentialTransactionError()
      }
      return { token, proof }
    }
    if (
      runtime.destroyed ||
      proofEpoch !== runtime.credentialEpoch ||
      runtime.accessToken !== token ||
      runtime.dpop !== proofKey
    ) {
      throw new StaleCredentialTransactionError()
    }
    return { token }
  }

  async function signDPoPProof(
    method: string,
    url: string,
  ): Promise<DPoPProofResult | undefined> {
    const token = await runtime.renewalOps.getToken()
    if (!token) return undefined
    const proofKey = runtime.dpop
    const proofEpoch = runtime.credentialEpoch
    const proof = proofKey
      ? await proofKey.signProof(method, url, {
          accessToken: token,
        })
      : undefined
    if (
      runtime.destroyed ||
      proofEpoch !== runtime.credentialEpoch ||
      runtime.accessToken !== token ||
      runtime.dpop !== proofKey
    ) {
      throw new StaleCredentialTransactionError()
    }
    return { token, proof }
  }

  async function seedTestSession(
    tokens: TokenResponse,
  ): Promise<AtolSession> {
    if (!runtime.allowTestSessions) {
      throw new Error(
        'seedTestSession is disabled: pass allowTestSessions:true to ' +
          'createAtolBrowserAuth to enable it. It bypasses OIDC signature, ' +
          'state, nonce, and DPoP-binding validation and must never be enabled ' +
          'in production.',
      )
    }
    warnIfSeedTokenNotFresh(tokens.access_token)
    await runtime.credentialOps.applyTokens(tokens, {
      testSession: true,
      credentialGeneration: credentialGenerationSnapshot(
        runtime.credentialGenerationBinding,
      ),
    })
    return runtime.sessionOps.session()
  }

  function onSessionChange(
    callback: (session: AtolSession) => void,
  ): () => void {
    runtime.subscribers.add(callback)
    try {
      callback(runtime.sessionOps.session())
    } catch {
      // Ignore subscriber errors on initial delivery.
    }
    return () => {
      runtime.subscribers.delete(callback)
    }
  }

  function destroy(): void {
    const firstAttempt = !runtime.destroyed
    if (firstAttempt) {
      runtime.destroyed = true
      runtime.credentialEpoch++
    }
    let cleanupFailed = false
    try {
      runtime.sessionOps.clearRenewTimer()
    } catch {
      cleanupFailed = true
    }
    if (runtime.broadcast) {
      const broadcast = runtime.broadcast
      try {
        broadcast.close()
        if (runtime.broadcast === broadcast) runtime.broadcast = null
      } catch {
        cleanupFailed = true
      }
    }
    if (runtime.removeCredentialGenerationStorageListener) {
      const removeListener =
        runtime.removeCredentialGenerationStorageListener
      try {
        removeListener()
        if (
          runtime.removeCredentialGenerationStorageListener ===
          removeListener
        ) {
          runtime.removeCredentialGenerationStorageListener = null
        }
      } catch {
        cleanupFailed = true
      }
    }
    runtime.subscribers.clear()
    runtime.dpop = null
    runtime.accessToken = undefined
    runtime.refreshToken = undefined
    runtime.currentUser = null
    runtime.currentIdToken = undefined
    runtime.currentOrganizationId = undefined
    runtime.activeCredentialGeneration = undefined
    if (!runtime.destroyUserStoreCleanupStarted) {
      try {
        const userStoreClear = runtime.enqueueUserStore(() =>
          runtime.manager.removeUser(),
        )
        runtime.destroyUserStoreCleanupStarted = true
        void userStoreClear.catch(() => {
          runtime.destroyUserStoreCleanupStarted = false
        })
      } catch {
        cleanupFailed = true
      }
    }
    runtime.sessionOps.zeroEncKey()
    runtime.encError = undefined
    if (
      typeof window !== 'undefined' &&
      !runtime.destroyAuthorizationCleanupStarted
    ) {
      try {
        const invalidation =
          runtime.sessionOps.invalidateAuthorizationAuthority(false)
        runtime.destroyAuthorizationCleanupStarted = true
        void invalidation.completion.catch(() => {
          runtime.destroyAuthorizationCleanupStarted = false
        })
      } catch {
        cleanupFailed = true
      }
    }
    if (cleanupFailed) {
      throw new AtolBrowserAuthCleanupError()
    }
  }

  const { canRestartLogin, restartLogin } =
    createBrowserAuthLoginRestart(runtime, beginLoginOnce)

  return {
    init: () => runtime.lifecycleOps.init(),
    beginLogin,
    stepUp,
    completeLogin: () => runtime.callbackOps.completeLogin(),
    selectOrganization,
    getAccessToken: getAccessTokenPublic,
    getIdToken: () => {
      if (runtime.currentIdToken) {
        runtime.sessionOps.assertLiveCredentialAuthority()
      }
      return runtime.currentIdToken
    },
    getEncryptionKey: () => {
      runtime.sessionOps.assertLiveCredentialAuthority()
      return runtime.encKey
    },
    getEncryptionError: () => {
      runtime.sessionOps.assertLiveCredentialAuthority()
      return runtime.encError
    },
    cancelLogin,
    canRestartLogin,
    restartLogin,
    logout,
    forceRenew: () => runtime.renewalOps.forceRenew(),
    signDPoPProof,
    isDPoPActive: () => runtime.dpop !== null,
    onSessionChange,
    seedTestSession,
    destroy,
  }
}
