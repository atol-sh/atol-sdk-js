/**
 * @atol-sh/js -- framework-agnostic browser security core for Atol.
 *
 * The keystone is {@link createAtolBrowserAuth}: a config-driven browser
 * auth client (OIDC Authorization Code + PKCE, in-memory tokens, DPoP,
 * silent renew, cross-tab coordination, RP-initiated logout). Framework
 * bindings (`@atol-sh/react`, ...) are thin wrappers over it.
 *
 * The lower-level primitives (DPoP key manager, ID token verification,
 * PKCE/token endpoint helpers, the KEK vault, permission loading) are also
 * exported for consumers that assemble their own flows.
 *
 * Device intelligence lives under the optional `@atol-sh/js/device`
 * subpath so it does not pull `@atol-sh/fingerprint` into bundles that
 * don't use it.
 */

// --- Keystone: config-driven browser auth client ---
export { createAtolBrowserAuth } from './client/browser-auth'
export type {
  AtolBrowserAuth,
  AtolBrowserAuthConfig,
  AtolSession,
  DPoPConfig,
  GetAccessTokenOptions,
  BeginLoginOptions,
  StepUpOptions,
} from './client/browser-auth'

// --- Shared types ---
export type {
  AtolUser,
  PermissionCheck,
  PermissionResult,
  DPoPProofResult,
} from './claims/types'

// --- Claims / JWT helpers ---
export { parseAtolUser, decodeJWTPayload, getTokenExpiry } from './claims/claims'

// --- DPoP (RFC 9449) ---
export { createDPoPKeyManager } from './dpop/dpop'
export type { DPoPKeyManager, DPoPProofOptions } from './dpop/dpop'

// --- ID token verification (JWKS) ---
export { verifyIdToken, _resetDiscoveryCache } from './verify/verify'

// --- OIDC / PKCE / token endpoint ---
export {
  createUserManager,
  getAccessToken,
  getIdToken,
  userFromTokenResponse,
} from './oidc/oidc'
export {
  silentAuthorize,
  silentAuthorizeWithRetry,
  exchangeCode,
  refreshTokenGrant,
  revokeToken,
  LoginRequiredError,
  DEFAULT_AUTHORIZE_TIMEOUT_MS,
  DEFAULT_SILENT_RENEW_RETRY_COUNT,
} from './oidc/silent-renew'
export type { TokenResponse, DPoPSigner } from './oidc/silent-renew'
export {
  OAuthProtocolError,
  NetworkError,
  RecoveryAction,
  classifyRenewalError,
  backoffDelay,
} from './oidc/token-recovery'
export { withTabLock, hasTabLockSupport } from './oidc/cross-tab-lock'

// --- Cross-tab token broadcast ---
export {
  createTokenBroadcast,
  hasBroadcastSupport,
} from './token/token-broadcast'
export type {
  TokenBroadcast,
  BroadcastMessage,
  TokenRotatedMessage,
  SessionExpiredMessage,
} from './token/token-broadcast'

// --- Permissions ---
export { loadPermissions, permissionKey } from './permissions/permissions'
export type { LoadPermissionsOptions } from './permissions/permissions'

// --- Zero-knowledge encryption primitives ---
export { KEKVault } from './crypto/kek-vault'
export {
  extractKEKFromFragment,
  kekBase64ToBytes,
  unwrapDEK,
} from './crypto/encryption'
export {
  base64ToBytes,
  bytesToBase64Url,
  stringToBase64Url,
} from './crypto/base64url'
