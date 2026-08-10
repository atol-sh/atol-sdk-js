import type { UserManager } from 'oidc-client-ts'
import type { AtolUser } from '../claims/types'
import { KEKVault } from '../crypto/kek-vault'
import type { DPoPKeyManager } from '../dpop/dpop'
import {
  createUserManager,
} from '../oidc/oidc'
import {
  logoutGenerationStorageKey,
  type CredentialGenerationBinding,
  type CredentialGenerationSnapshot,
} from '../oidc/credential-generation'
import type { OrdinaryAuthorizationExchangeBinding } from '../oidc/ordinary-authorization-exchange'
import { OrdinaryBrowserAuthorization } from '../oidc/ordinary-authorization'
import {
  ResponseVault,
  type ResponseVaultGrant,
} from '../oidc/response-vault'
import type { TokenResponse } from '../oidc/silent-renew'
import { normalizeSameOriginReturnTo } from '../oidc/return-to'
import type { TokenBroadcast } from '../token/token-broadcast'
import type {
  AtolBrowserAuthConfig,
  AtolSession,
} from './browser-auth'
import {
  DEFAULT_SCOPES,
  dpopEnabled,
  dpopRequired,
  normalizePostLogoutRedirectURI,
} from './browser-auth-support'

export interface ApplyTokenOptions {
  testSession?: boolean
  expectedOrganizationId?: string
  enforceExpectedOrganization?: boolean
  preserveExistingTokens?: boolean
  epoch?: number
  expectedNonce?: string
  advanceEpochOnCommit?: boolean
  dpopKey?: DPoPKeyManager | null
  replaceDPoPKey?: boolean
  credentialGeneration?: CredentialGenerationSnapshot
  requireLiveCredentialAuthority?: boolean
}

export interface PreparedCredentials {
  accessToken: string
  idToken: string
  refreshToken?: string
  tokenType: string
  organizationId?: string
  user: AtolUser
}

export interface PreparedEncryptionState {
  replace: boolean
  key?: Uint8Array
  error?: Error
}

export interface SilentCredentialGrant {
  tokens: TokenResponse
  nonce: string
  dpopKey: DPoPKeyManager | null
  responseVaultGrant?: ResponseVaultGrant
  ordinaryAuthorizationGrant?: {
    complete(): Promise<void>
    compensate(): Promise<void>
  }
}

export interface AuthorizationInvalidation {
  completion: Promise<void>
  logoutGeneration?: string
}

export interface BrowserAuthSessionOperations {
  session(): AtolSession
  emit(): void
  getVault(): KEKVault
  zeroEncKey(): void
  prepareEncryptionState(idToken: string): Promise<PreparedEncryptionState>
  clearRenewTimer(): void
  scheduleRenew(): void
  assertCredentialAuthority(
    generation: CredentialGenerationSnapshot | undefined,
  ): void
  assertLiveCredentialAuthority(
    expected?: CredentialGenerationSnapshot,
  ): void
  requireLiveCredentialGeneration(): CredentialGenerationSnapshot
  assertApplyCredentialAuthority(options: ApplyTokenOptions): void
  invalidateAuthorizationAuthority(
    rotateLogout: boolean,
  ): AuthorizationInvalidation
  clearSession(): Promise<void>
  installCredentialGenerationStorageListener(): void
}

export interface BrowserAuthCredentialOperations {
  applyTokens(
    tokens: TokenResponse,
    options?: ApplyTokenOptions,
  ): Promise<void>
  applyAuthorizationGrant(
    grant: SilentCredentialGrant,
    options: ApplyTokenOptions,
  ): Promise<void>
}

export interface BrowserAuthRenewalOperations {
  renewViaIframe(
    organizationId: string | undefined,
    expectedGeneration: CredentialGenerationSnapshot,
    requireLiveAuthority?: boolean,
  ): Promise<SilentCredentialGrant>
  renewSingleFlight(
    force: boolean,
    publishSignal: boolean,
  ): Promise<string | undefined>
  getToken(): Promise<string | undefined>
  forceRenew(): Promise<string | undefined>
  onBroadcast(message: import('../token/token-broadcast').BroadcastMessage): Promise<void>
}

export interface BrowserAuthLifecycleOperations {
  isCallbackUrl(): boolean
  isPostLogoutCallbackUrl(): boolean
  settleSignedOutStartup(expectedLogoutGeneration: string): Promise<boolean>
  ensureRuntimeInitialized(): Promise<void>
  restoreSession(): Promise<void>
  init(): Promise<AtolSession>
}

export interface BrowserAuthCallbackOperations {
  completeLogin(): Promise<AtolSession>
}

export class BrowserAuthRuntime {
  readonly issuer: string
  readonly clientId: string
  readonly audience: string | undefined
  readonly redirectUri: string
  readonly postLogoutRedirectUri: string
  readonly credentialGenerationBinding: CredentialGenerationBinding
  readonly credentialGenerationStorageKey: string
  readonly useResponseVault: boolean
  readonly useDPoP: boolean
  readonly requireDPoP: boolean
  readonly ordinaryExchangeBinding: OrdinaryAuthorizationExchangeBinding
  readonly useRefreshTokens: boolean
  readonly useRefreshTokensFallback: boolean
  readonly deriveEncryptionKey: boolean
  readonly allowTestSessions: boolean
  readonly initialTestSession: TokenResponse | undefined
  readonly scope: string
  readonly manager: UserManager
  readonly responseVault: ResponseVault | null
  readonly ordinaryAuthorization: OrdinaryBrowserAuthorization | null

  currentUser: AtolUser | null = null
  currentIdToken: string | undefined
  currentOrganizationId: string | undefined
  accessToken: string | undefined
  refreshToken: string | undefined
  activeCredentialGeneration: CredentialGenerationSnapshot | undefined
  encKey: Uint8Array | undefined
  encError: Error | undefined
  fragmentKEK: string | null = null
  vault: KEKVault | null = null
  dpop: DPoPKeyManager | null = null
  broadcast: TokenBroadcast | null = null
  renewTimer: ReturnType<typeof setTimeout> | null = null
  renewInFlight: {
    epoch: number
    promise: Promise<string | undefined>
  } | null = null
  renewBackoff = 0
  restoreInFlight: Promise<SilentCredentialGrant> | null = null
  runtimeInitPromise: Promise<void> | null = null
  removeCredentialGenerationStorageListener: (() => void) | null = null
  logoutInFlight: Promise<void> | null = null
  cancelLoginInFlight: Promise<void> | null = null
  pendingLogoutRefreshToken: string | undefined
  pendingLogoutIdToken: string | undefined
  credentialEpoch = 0
  destroyed = false
  destroyAuthorizationCleanupStarted = false
  destroyUserStoreCleanupStarted = false
  completeLoginPromise: Promise<AtolSession> | null = null
  initPromise: Promise<AtolSession> | null = null

  readonly subscribers = new Set<(session: AtolSession) => void>()
  private userStoreTail: Promise<void> = Promise.resolve()
  private authorizationActionTail: Promise<void> = Promise.resolve()
  credentialMutationTail: Promise<void> = Promise.resolve()

  sessionOps!: BrowserAuthSessionOperations
  credentialOps!: BrowserAuthCredentialOperations
  renewalOps!: BrowserAuthRenewalOperations
  lifecycleOps!: BrowserAuthLifecycleOperations
  callbackOps!: BrowserAuthCallbackOperations

  constructor(config: AtolBrowserAuthConfig) {
    this.issuer = config.issuer
    this.clientId = config.clientId
    this.audience = config.audience
    this.redirectUri = config.redirectUri
    this.credentialGenerationBinding = {
      issuer: this.issuer,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
    }
    this.credentialGenerationStorageKey = logoutGenerationStorageKey(
      this.credentialGenerationBinding,
    )
    this.useResponseVault = config.responseVault ?? false
    if (
      this.useResponseVault &&
      config.postLogoutRedirectUri === undefined
    ) {
      throw new Error(
        'response-vault authorization requires postLogoutRedirectUri',
      )
    }
    this.postLogoutRedirectUri =
      config.postLogoutRedirectUri === undefined
        ? this.redirectUri
        : normalizePostLogoutRedirectURI(
            config.postLogoutRedirectUri,
            this.redirectUri,
          )
    if (
      this.useResponseVault &&
      this.postLogoutRedirectUri === new URL(this.redirectUri).href
    ) {
      throw new Error(
        'response-vault postLogoutRedirectUri must differ from redirectUri',
      )
    }
    if (this.useResponseVault && config.dpop === false) {
      throw new Error('response-vault authorization requires DPoP')
    }
    if (this.useResponseVault && !this.audience) {
      throw new Error('response-vault authorization requires an audience')
    }
    this.useDPoP = this.useResponseVault || dpopEnabled(config.dpop)
    this.requireDPoP =
      this.useResponseVault || dpopRequired(config.dpop)
    this.ordinaryExchangeBinding = {
      issuer: this.issuer,
      clientId: this.clientId,
      useDPoP: this.useDPoP,
      requireDPoP: this.requireDPoP,
    }
    this.useRefreshTokens = config.useRefreshTokens ?? false
    this.useRefreshTokensFallback =
      config.useRefreshTokensFallback ?? false
    this.deriveEncryptionKey = config.deriveEncryptionKey ?? false
    if (this.useResponseVault && this.deriveEncryptionKey) {
      throw new Error(
        'response-vault v1 does not support deriveEncryptionKey',
      )
    }
    this.allowTestSessions = config.allowTestSessions ?? false
    this.initialTestSession = this.allowTestSessions
      ? config.initialTestSession
      : undefined
    if (
      this.allowTestSessions &&
      typeof console !== 'undefined'
    ) {
      console.warn(
        '[Atol] allowTestSessions is ENABLED: seedTestSession can establish a ' +
          'session without OIDC validation. This is for tests only and must ' +
          'never be enabled in production.',
      )
    }
    const requestedScopes = config.scopes ?? DEFAULT_SCOPES
    this.scope =
      this.useRefreshTokens &&
      !requestedScopes.split(' ').includes('offline_access')
        ? `${requestedScopes} offline_access`
        : requestedScopes
    this.manager = createUserManager(
      this.issuer,
      this.clientId,
      this.redirectUri,
      this.scope,
      this.audience,
    )
    this.responseVault = this.useResponseVault
      ? new ResponseVault({
          issuer: this.issuer,
          clientId: this.clientId,
          redirectUri: this.redirectUri,
          audience: this.audience as string,
          scope: this.scope,
        })
      : null
    this.ordinaryAuthorization = this.responseVault
      ? null
      : new OrdinaryBrowserAuthorization(this.manager, {
          issuer: this.issuer,
          clientId: this.clientId,
          redirectUri: this.redirectUri,
          scope: this.scope,
        })
  }

  applyReturnTo(returnTo: string | undefined): boolean {
    if (returnTo === undefined) return false
    if (typeof window === 'undefined') {
      throw new Error('returnTo cannot be applied outside a browser')
    }
    const route = normalizeSameOriginReturnTo(
      returnTo,
      this.redirectUri,
    )
    if (
      route !== returnTo ||
      window.location.origin !== new URL(this.redirectUri).origin
    ) {
      throw new Error(
        'returnTo no longer matches the authorization binding',
      )
    }
    window.history.replaceState({}, document.title, route)
    window.dispatchEvent(
      new window.PopStateEvent('popstate', {
        state: window.history.state,
      }),
    )
    return true
  }

  enqueueUserStore(operation: () => Promise<void>): Promise<void> {
    const result = this.userStoreTail.then(operation)
    this.userStoreTail = result.catch(() => undefined)
    return result
  }

  enqueueAuthorizationAction<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    const result = this.authorizationActionTail.then(operation)
    this.authorizationActionTail = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }

  enqueueCredentialMutation<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    const result = this.credentialMutationTail.then(operation)
    this.credentialMutationTail = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }
}
