# Changelog

All notable changes to `@atol-sh/js` are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes yet.

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

[Unreleased]: https://github.com/atol-sh/atol-sdk-js/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/atol-sh/atol-sdk-js/releases/tag/v0.1.0
