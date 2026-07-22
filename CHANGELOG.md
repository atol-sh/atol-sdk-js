# Changelog

All notable changes to `@atol-sh/js` are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-21

### Added

- `selectOrganization(organizationId)` starts a distinct `prompt=none`
  organization grant and exposes the committed credential context as
  `AtolSession.organizationId`.
- `DPoPKeyManager.thumbprint()` exposes the RFC 7638 thumbprint used to
  validate access-token `cnf.jkt` binding.

### Changed

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
  authenticated session directly from a token response — bypassing the OIDC
  redirect/callback and signature/state/nonce checks — so browser e2e tests
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
  `verifyIdToken` (JWKS), `createUserManager` / `silentAuthorize` /
  `exchangeCode` / `refreshTokenGrant` / `revokeToken`,
  `createTokenBroadcast`, `withTabLock`, `loadPermissions`, `KEKVault` +
  zero-knowledge encryption helpers, and JWT claim helpers.
- Optional `@atol-sh/js/device` subpath: `DeviceCollector` and device
  intelligence types, isolating the optional `@atol-sh/fingerprint` peer
  dependency from the core bundle.
- Dual ESM/CJS build (tsup) with type declarations for both entry points.
- Tokens are memory-only: access/ID/refresh tokens never touch Web Storage;
  `sessionStorage` holds only the OIDC state/PKCE verifier.

[Unreleased]: https://github.com/atol-sh/atol-sdk-js/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/atol-sh/atol-sdk-js/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/atol-sh/atol-sdk-js/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/atol-sh/atol-sdk-js/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/atol-sh/atol-sdk-js/releases/tag/v0.1.0
