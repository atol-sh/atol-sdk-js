import { decodeJWTPayload, getTokenExpiry } from '../claims/claims'
import { KEKVault } from '../crypto/kek-vault'
import { kekBase64ToBytes } from '../crypto/encryption'
import {
  assertCredentialGenerationSnapshot,
  credentialGenerationSnapshot,
  persistedCredentialAuthority,
  rotateLogoutGeneration,
  rotateTabOwnerGeneration,
  type CredentialGenerationSnapshot,
} from '../oidc/credential-generation'
import { backoffDelay } from '../oidc/token-recovery'
import type {
  ApplyTokenOptions,
  BrowserAuthRuntime,
  BrowserAuthSessionOperations,
  PreparedEncryptionState,
} from './browser-auth-context'
import {
  RENEW_WINDOW_MS,
  StaleCredentialTransactionError,
} from './browser-auth-support'

class EncryptionKeyUnavailableError extends Error {
  readonly code = 'encryption_key_unavailable'

  constructor() {
    super(
      'Encryption key unavailable. Sign in again or clear this site\'s stored data.',
    )
    this.name = 'EncryptionKeyUnavailableError'
  }
}

export function createBrowserAuthSessionOperations(
  runtime: BrowserAuthRuntime,
): BrowserAuthSessionOperations {
  function session() {
    assertLiveCredentialAuthority()
    return {
      isAuthenticated: runtime.currentUser !== null,
      user: runtime.currentUser,
      organizationId: runtime.currentOrganizationId,
      encryptionKey: runtime.encKey,
      encryptionError: runtime.encError,
    }
  }

  function emit(): void {
    const snapshot = session()
    for (const subscriber of runtime.subscribers) {
      try {
        subscriber(snapshot)
      } catch {
        // A subscriber cannot interrupt credential settlement.
      }
    }
  }

  function getVault(): KEKVault {
    return (runtime.vault ??= new KEKVault())
  }

  function wrappedDEKFromIdToken(
    idToken: string | undefined,
  ): string | undefined {
    if (!idToken) return undefined
    try {
      const claim = decodeJWTPayload(idToken)['atol:wrapped_dek']
      return typeof claim === 'string' && claim !== ''
        ? claim
        : undefined
    } catch {
      return undefined
    }
  }

  function zeroEncKey(): void {
    if (runtime.encKey) {
      for (let i = 0; i < runtime.encKey.length; i++) {
        runtime.encKey[i] = 0
      }
    }
    runtime.encKey = undefined
  }

  async function prepareEncryptionState(
    idToken: string,
  ): Promise<PreparedEncryptionState> {
    if (!runtime.deriveEncryptionKey || runtime.encKey) {
      return { replace: false }
    }
    const wrappedDEK = wrappedDEKFromIdToken(idToken)
    if (runtime.fragmentKEK) {
      const kek = runtime.fragmentKEK
      runtime.fragmentKEK = null
      if (!wrappedDEK) return { replace: false }
      try {
        return {
          replace: true,
          key: await getVault().provision(
            kekBase64ToBytes(kek),
            wrappedDEK,
          ),
        }
      } catch {
        await getVault().clear().catch(() => undefined)
        return {
          replace: true,
          error: new EncryptionKeyUnavailableError(),
        }
      }
    }
    if (!wrappedDEK) return { replace: false }
    try {
      const key = await getVault().rehydrate(wrappedDEK)
      return key ? { replace: true, key } : { replace: false }
    } catch {
      await getVault().clear().catch(() => undefined)
      return {
        replace: true,
        error: new EncryptionKeyUnavailableError(),
      }
    }
  }

  function clearRenewTimer(): void {
    if (!runtime.renewTimer) return
    clearTimeout(runtime.renewTimer)
    runtime.renewTimer = null
  }

  function scheduleRenew(): void {
    clearRenewTimer()
    if (!runtime.accessToken) return
    const exp = getTokenExpiry(runtime.accessToken)
    if (exp === null) return
    const baseDelay = Math.max(
      0,
      exp - RENEW_WINDOW_MS - Date.now(),
    )
    const delay = baseDelay + backoffDelay(runtime.renewBackoff)
    runtime.renewTimer = setTimeout(() => {
      void runtime.renewalOps
        .renewSingleFlight(false, true)
        .catch(() => undefined)
    }, delay)
  }

  function assertCredentialAuthority(
    generation: CredentialGenerationSnapshot | undefined,
  ): void {
    if (generation) {
      assertCredentialGenerationSnapshot(
        runtime.credentialGenerationBinding,
        generation,
      )
    }
  }

  function sameCredentialGeneration(
    left: CredentialGenerationSnapshot,
    right: CredentialGenerationSnapshot,
  ): boolean {
    return (
      left.logout === right.logout &&
      left.tabOwner === right.tabOwner
    )
  }

  function rejectStaleLiveCredentialAuthority(): never {
    void clearSession()
    throw new StaleCredentialTransactionError()
  }

  function assertLiveCredentialAuthority(
    expected?: CredentialGenerationSnapshot,
  ): void {
    const active = runtime.activeCredentialGeneration
    if (!active) {
      if (expected) throw new StaleCredentialTransactionError()
      return
    }
    if (expected && !sameCredentialGeneration(active, expected)) {
      try {
        assertCredentialAuthority(active)
      } catch {
        rejectStaleLiveCredentialAuthority()
      }
      throw new StaleCredentialTransactionError()
    }
    try {
      assertCredentialAuthority(active)
    } catch {
      rejectStaleLiveCredentialAuthority()
    }
  }

  function requireLiveCredentialGeneration():
    CredentialGenerationSnapshot {
    const generation = runtime.activeCredentialGeneration
    if (!generation) throw new StaleCredentialTransactionError()
    assertLiveCredentialAuthority(generation)
    return generation
  }

  function assertApplyCredentialAuthority(
    options: ApplyTokenOptions,
  ): void {
    if (options.requireLiveCredentialAuthority) {
      if (!options.credentialGeneration) {
        throw new StaleCredentialTransactionError()
      }
      assertLiveCredentialAuthority(options.credentialGeneration)
      return
    }
    assertCredentialAuthority(options.credentialGeneration)
  }

  function invalidateAuthorizationAuthority(
    rotateLogout: boolean,
  ) {
    if (runtime.responseVault) {
      const completion =
        runtime.responseVault.invalidateLifecycle(rotateLogout)
      if (!rotateLogout) return { completion }
      let logoutGeneration: string | undefined
      try {
        const authority = persistedCredentialAuthority(
          runtime.credentialGenerationBinding,
        )
        logoutGeneration = authority?.signedOut
          ? authority.generation
          : undefined
      } catch {
        // invalidateLifecycle carries the authoritative storage failure.
      }
      return { completion, logoutGeneration }
    }
    if (!rotateLogout) {
      return { completion: Promise.resolve() }
    }
    let firstError: unknown
    let logoutGeneration: string | undefined
    let ordinaryCleanup = Promise.resolve()
    try {
      ordinaryCleanup =
        runtime.ordinaryAuthorization!.invalidateCurrent(
          credentialGenerationSnapshot(
            runtime.credentialGenerationBinding,
          ),
        )
    } catch (error) {
      firstError = error
    }
    try {
      logoutGeneration = rotateLogoutGeneration(
        runtime.credentialGenerationBinding,
      )
    } catch (error) {
      firstError ??= error
    }
    try {
      rotateTabOwnerGeneration(
        runtime.credentialGenerationBinding,
      )
    } catch (error) {
      firstError ??= error
    }
    return {
      completion: ordinaryCleanup
        .catch((error) => {
          throw firstError ?? error
        })
        .then(() => {
          if (firstError !== undefined) throw firstError
        }),
      logoutGeneration,
    }
  }

  function clearSession(): Promise<void> {
    runtime.credentialEpoch++
    clearRenewTimer()
    runtime.accessToken = undefined
    runtime.refreshToken = undefined
    runtime.currentUser = null
    runtime.currentIdToken = undefined
    runtime.currentOrganizationId = undefined
    runtime.activeCredentialGeneration = undefined
    zeroEncKey()
    runtime.encError = undefined
    const userStoreClear = runtime.enqueueUserStore(() =>
      runtime.manager.removeUser(),
    )
    void userStoreClear.catch(() => undefined)
    emit()
    return userStoreClear
  }

  function onCredentialGenerationStorage(
    event: StorageEvent,
  ): void {
    if (
      runtime.destroyed ||
      event.key !== runtime.credentialGenerationStorageKey ||
      !runtime.activeCredentialGeneration
    ) {
      return
    }
    let persisted: ReturnType<typeof persistedCredentialAuthority>
    try {
      if (
        typeof window === 'undefined' ||
        event.newValue !==
          window.localStorage.getItem(
            runtime.credentialGenerationStorageKey,
          )
      ) {
        return
      }
      persisted = persistedCredentialAuthority(
        runtime.credentialGenerationBinding,
      )
    } catch {
      void clearSession()
      return
    }
    if (
      persisted !== null &&
      persisted.generation ===
        runtime.activeCredentialGeneration.logout
    ) {
      return
    }
    void clearSession()
  }

  function installCredentialGenerationStorageListener(): void {
    if (
      runtime.removeCredentialGenerationStorageListener ||
      typeof window === 'undefined'
    ) {
      return
    }
    const target = window
    target.addEventListener(
      'storage',
      onCredentialGenerationStorage,
    )
    runtime.removeCredentialGenerationStorageListener = () => {
      target.removeEventListener(
        'storage',
        onCredentialGenerationStorage,
      )
    }
  }

  return {
    session,
    emit,
    getVault,
    zeroEncKey,
    prepareEncryptionState,
    clearRenewTimer,
    scheduleRenew,
    assertCredentialAuthority,
    assertLiveCredentialAuthority,
    requireLiveCredentialGeneration,
    assertApplyCredentialAuthority,
    invalidateAuthorizationAuthority,
    clearSession,
    installCredentialGenerationStorageListener,
  }
}
