# Changelog

All notable changes to `@atol-sh/js` are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - Staged, unpublished

This staged release consolidates every change since the last published version,
0.1.2. It has no publication date or release tag because registry publication
and integrity verification have not completed.

### Added

- `AtolBrowserAuth.cancelLogin()` exact-fences and rejects an abandoned
  response-vault interactive authorization without performing RP logout
  navigation or exposing browser custody. Login and cancellation are ordered
  through one client-local queue, concurrent callers retain exact
  single-flight promise identity, and retry custody persists an
  `interactive_cancel` provenance that cannot match iframe renewal. Damaged
  local key custody remains cancellable only when its durable source mode
  proves an interactive grant, and destroy-cleanup ownership begins only after
  the durable cancellation claim succeeds.
- Ordinary browser authorization protocol v2 now performs credentialless form
  PAR before navigation, carries only the rooted `client_id` and
  `request_uri` envelope through the browser, and supports byte-identical
  pre-navigation cancellation plus proof-bound terminal settlement.
- `responseVault: true` enables the public response-vault v1 protocol:
  JSON PAR and issuer-init requests, parameter-free authorize/callback
  navigation, same-origin relay, capability acknowledgement and finalization,
  and durable exact-family rejection.
- OIDC discovery publishes the registered v1 binding and bootstrap, PAR,
  issuer-init, authorize, relay, acknowledgement, finalization, and rejection
  endpoints.
- `beginLogin({ returnTo })` and `stepUp({ returnTo })` restore a canonical
  same-origin application route after verified credentials commit. The route
  is transaction-bound state and never changes the registered redirect URI.
- `postLogoutRedirectUri` separates the registered RP-initiated logout landing
  page from the authorization callback. Response-vault mode requires it.
- `selectOrganization(organizationId)` starts a distinct `prompt=none`
  organization grant and exposes the committed credential context as
  `AtolSession.organizationId`.
- `DPoPKeyManager.thumbprint()` exposes the RFC 7638 thumbprint used to
  validate access-token `cnf.jkt` binding.

### Changed

- The optional device collector now passes an operation-scoped authorization
  owner to the fingerprint SDK. It acquires a Bearer token or an inseparable
  DPoP token/proof pair for the exact identify URL and retains neither.
- The optional device collector independently validates the exact identify
  response, including device-mismatch and device-sharing signals. Missing,
  unknown, or mistyped fields fail closed instead of being defaulted.
- Device identify responses require a non-null exact 13-field smart-signal
  object. A caller-supplied non-secret credential generation makes every new
  credential intent fence late responses from older in-flight requests.
- Device collection snapshots only the accepted generation and authorization
  owner before asynchronous work. Invalidation permanently fences every
  accepted generation, and dependency preloading cannot replace authenticated
  device state.
- Every response-vault interactive, silent, organization-selection, and step-up
  grant now creates a fresh non-extractable DPoP key. The matching key is
  adopted only after the relayed tokens pass issuer, audience, nonce, subject,
  organization, token-type, and `cnf.jkt` validation.
- Resource DPoP results now fence the exact token, key, and credential epoch
  across asynchronous signing. Logout, renewal, organization selection, or
  destroy cannot return a stale token/proof pair.
- Browser client teardown retries any channel or listener step that throws.
  Partial teardown remains destroyed and surfaces only the closed
  `browser_auth_cleanup_failed` diagnostic until every retained step closes.
  A completed abandoned-login cancellation suppresses duplicate destroy
  cleanup until a later explicit `beginLogin()` successfully establishes new
  interactive custody.
- Interactive callbacks now consume oidc-client-ts state/PKCE through its
  public APIs, use the SDK's DPoP-aware code exchange, and verify ID-token
  signature, issuer, audience, required claims, and callback nonce.
- Token responses commit atomically only after access/ID subjects and
  organization claims agree. Organization selection is isolated from older
  generic renewal results.
- Cross-tab coordination is signal-only. Tokens never travel through
  `BroadcastChannel`; each tab renews with its own DPoP key and grant.
- `AtolUser` no longer exposes organization, plan, or role claims. Selected
  organization is credential context, not user identity.

### Security

- Ordinary PAR accepts only an exact parameter-free `application/json`
  response and every authenticated PAR, cancellation, or settlement outcome
  requires the exposed `Atol-Browser-Authorization: v2` signal. Hidden
  `Access-Control-Allow-Origin`, `Vary`, and
  `Access-Control-Allow-Credentials` headers are never treated as browser
  authority; missing, unexposed, repeated, or unequal signals preserve
  custody.
- Logout now persists one atomic generation and signed-out authority record
  before asynchronous teardown. Cold startup retries application-wide
  response-vault cancellation, suppresses IdP-cookie silent restoration, and
  stays signed out without `BroadcastChannel`; only explicit login installs a
  fresh active generation.
- RP-initiated logout uses one-use validated callback state. Refresh-token
  revocation, response-vault cleanup, local vault clearing, and end-session
  navigation failures remain visible while the durable tombstone prevents
  session resurrection.
- Response-vault authorization codes, OAuth state, OIDC nonce, PKCE material,
  pushed request URI, transaction ID, and tokens no longer cross browser
  navigation URLs or `postMessage`.
- Relay transport loss resumes the same durable transaction and key.
  A random PAR idempotency key makes an ambiguous push return the exact same
  transaction, and a separate cancellation capability settles it after
  cookie and CSRF authority is cleared.
- Acknowledgement deletes the encrypted delivery and enters bounded
  `publishing`; local credential commit is followed by a separate,
  idempotently retryable finalization to `adopted`. Publication failure
  compensates by revoking the exact family, including during the bounded
  post-finalize window.
- `completePublication()` atomically changes local `adopted` custody to
  `published` and releases the host-wide live slot. Ordinary crash scans
  compensate abandoned `adopted` custody but exclude clean `published`
  custody; explicit logout includes both.
- After a reload, an acknowledged success that is unavailable from memory is
  rejected before one fresh silent grant is obtained. Durable terminal
  settlements re-surface the exact typed OAuth error instead of using success
  recovery. The validated return route remains behind one private, one-shot
  recovery capability and is never retained on the public error. Bearer
  material is never persisted.
- Invalid, stale, or navigation-failed response-vault grants persist rejection
  before transport. Exact retries revoke any issued token family, consume the
  server transaction, and never create another relay or grant.
- Random origin-wide logout and per-tab owner generations fence ordinary and
  response-vault callbacks across reloads and missed broadcasts. A durable
  client-origin slot gives concurrent starts across tabs and bindings one
  winner.
- Protocol response bodies are consumed with a 32 KiB streaming cap under the
  operation deadline. Lifecycle invalidation aborts outstanding fetches and
  retry waits.
- Response-vault mode requires DPoP and a non-empty registered audience, and
  rejects the incompatible `deriveEncryptionKey` URL-fragment flow.
- Token-endpoint `DPoP-Nonce` fields are parsed once using bounded RFC 9449
  syntax. Comma-joined duplicates, whitespace, control characters, and
  malformed values are rejected without replacing the last valid nonce. A
  transport rejection or malformed header after an authorization code was
  dispatched returns the closed `authorization_code_exchange_uncertain`
  diagnostic, never a definite local failure.
- Response-vault cleanup failures collapse to one closed code and message.
  Public errors retain neither raw caught values nor nested error arrays.
  Active-custody recovery reconstructs only named authorization diagnostics;
  decorated errors, storage, WebCrypto, and hostile caught values collapse to
  clean diagnostics. An earlier cleanup failure remains authoritative when
  grant rejection also fails.
- Response-vault Web Locks are physically released after IndexedDB failures,
  fence assertion failures, and lifecycle-cancelled retry waits. Durable
  custody is never deleted by that release; a new contender must reacquire the
  same browser lock and revalidate the persisted fence. When operation and
  cleanup both fail, the original failure remains primary while internal
  diagnostics retain the ordered cleanup failures outside public error fields.
- DPoP responses now require `token_type=DPoP` and an access-token `cnf.jkt`
  matching the active tab key. `{ dpop: { required: true } }` fails init when
  WebCrypto cannot create that key.
- Access tokens are verified as signed `at+jwt` credentials for the configured
  resource before their subject, organization, or DPoP binding is trusted.
- Interactive callback state without a nonce is rejected. Callback completion
  is single-flight, owns bounded failure cleanup, and cannot commit after the
  client is destroyed.
- Only typed transport failures are retried; configuration, URL, and WebCrypto
  `TypeError` failures surface immediately.
- Package type checking now includes all tests and protocol mocks.

## [0.1.2] - 2026-07-08

### Added

- `initialTestSession` config option (gated on `allowTestSessions`). When set,
  `createAtolBrowserAuth(...).init()` adopts the given token response
  deterministically and SKIPS the cold-load restore entirely -- no
  redirect-callback handling, no hidden-iframe silent renew. The session settles
  authenticated at first paint, race-free (unlike calling `seedTestSession`
  after mount). This is the clean way to bootstrap a browser e2e session against
  a stubbed backend with no IdP at the `issuer`, where the restore iframe would
  otherwise block until it times out. Ignored unless `allowTestSessions: true`;
  warns when the token has no future `exp`.

## [0.1.1] - 2026-07-08

### Added

- `seedTestSession(tokens)` on the browser auth client, gated behind a new
  `allowTestSessions` config flag (default `false`). It establishes an
  authenticated session directly from a token response -- bypassing the OIDC
  redirect/callback and signature/state/nonce checks -- so browser e2e tests
  can bootstrap a logged-in session against the in-memory token store without
  a live IdP. Adopted through the same `applyTokens` path as a real login, so
  `onSessionChange` subscribers flip to authenticated. Deny-by-default: it
  throws unless `allowTestSessions: true`; enabling it logs a one-time
  `console.warn`, and seeding a token without a future `exp` warns too (such a
  token triggers an immediate renewal that can drop the session). Never enable
  in production. Consumed by `@atol-sh/react/testing`.

## [0.1.0] - 2026-07-05

Initial release. Framework-agnostic browser security core extracted from
`@atol-sh/react` so non-React bindings can share the same proven logic.

### Added

- `createAtolBrowserAuth`: config-driven browser auth client. OIDC
  Authorization Code + PKCE login, memory-only token storage, DPoP-aware
  `getAccessToken`, proactive + on-demand silent renewal with single-flight
  and cross-tab coordination, RP-initiated logout, and `onSessionChange`
  subscriptions. Cross-tab token adoption is authenticated (ID token
  verified against the IdP JWKS + subject pinning) before any rotated token
  is applied.
- Renewal model: hidden-iframe silent authentication against the IdP
  session cookie (`prompt=none`) is the default. No refresh token is
  requested or stored, and DPoP still binds the iframe code exchange.
  Opt into refresh tokens with `useRefreshTokens: true` (default `false`)
  only for cross-site apps where third-party-cookie policies block the
  iframe; that appends `offline_access`, renews via the refresh-token
  grant, and revokes the refresh token on logout. Same-site apps (a console
  on a subdomain of the IdP) should leave it `false`.
- Lower-level primitives: `createDPoPKeyManager` (RFC 9449),
  `verifyIdToken` (JWKS), `createUserManager` / `exchangeCode` /
  `refreshTokenGrant` / `revokeToken`,
  `createTokenBroadcast`, `withTabLock`, `loadPermissions`, `KEKVault` +
  zero-knowledge encryption helpers, and JWT claim helpers.
- Browser authorization, including `prompt=none` iframe renewal, is admitted
  through durable ordinary PAR before navigation.
- Optional `@atol-sh/js/device` subpath: `DeviceCollector` and device
  intelligence types, isolating the optional `@atol-sh/fingerprint` peer
  dependency from the core bundle.
- Dual ESM/CJS build (tsup) with type declarations for both entry points.
- Tokens are memory-only: access/ID/refresh tokens never touch Web Storage;
  `sessionStorage` holds only the OIDC state/PKCE verifier.

[Unreleased]: https://github.com/atol-sh/atol-sdk-js/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/atol-sh/atol-sdk-js/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/atol-sh/atol-sdk-js/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/atol-sh/atol-sdk-js/releases/tag/v0.1.0
