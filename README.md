# @atol-sh/js

[![npm version](https://img.shields.io/npm/v/@atol-sh/js.svg)](https://www.npmjs.com/package/@atol-sh/js)
[![CI](https://github.com/atol-sh/atol-sdk-js/actions/workflows/ci.yml/badge.svg)](https://github.com/atol-sh/atol-sdk-js/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@atol-sh/js.svg)](./LICENSE)

Framework-agnostic browser security core for [Atol](https://atol.sh): a
single config-driven client for OIDC authentication (Authorization Code +
PKCE), DPoP sender-constrained tokens (RFC 9449), silent renewal, cross-tab
coordination, and permission loading. `@atol-sh/react` is the React
binding, built as a thin wrapper over this same core -- future Vue,
Svelte, and vanilla-JS bindings will share it too.

Building a React app? Use [`@atol-sh/react`](https://github.com/atol-sh/atol-sdk-react)
instead, the React binding over this core. Either way you'll need a
publishable key id (`atol_kid_...`) -- get one from [console.atol.sh](https://console.atol.sh).

## Install

```bash
npm install @atol-sh/js
```

## Quickstart

The keystone export is `createAtolBrowserAuth`. Everything else in the
package is a lower-level primitive it is built from.

```ts
import { createAtolBrowserAuth } from '@atol-sh/js'

const auth = createAtolBrowserAuth({
  issuer: 'https://id.atol.sh',        // OIDC issuer URL
  clientId: 'atol_kid_abc123',         // publishable key id, safe for the browser
  audience: 'https://api.example.com', // optional API audience
  scopes: 'openid profile email',      // optional; used verbatim (no offline_access by default)
  redirectUri: 'https://app.example.com/callback',
  dpop: true,                          // optional RFC 9449 sender-constrained tokens
  useRefreshTokens: false,             // default (same-site); REQUIRED true for cross-site apps
  storage: 'memory',                   // tokens are always memory-only
})

const unsubscribe = auth.onSessionChange(({ isAuthenticated, user }) => {
  render(isAuthenticated, user)
})

// On startup: handles a redirect callback, or silently restores a session
// from the IdP session cookie.
await auth.init()

// Start a login (redirects the browser):
await auth.beginLogin()

// On the redirect URI page: exchange the code for tokens. init() calls
// this automatically, so most apps never call it directly.
await auth.completeLogin()

// Get a token for an API call (DPoP-aware: pass the request you're about
// to make so the proof's `htm`/`htu` bind to it):
const result = await auth.getAccessToken({
  dpop: { method: 'GET', url: 'https://api.example.com/me' },
})
if (result) {
  const headers = result.proof
    ? { Authorization: `DPoP ${result.token}`, DPoP: result.proof }
    : { Authorization: `Bearer ${result.token}` }
}

// Sign out (revokes the refresh token, then RP-initiated end_session):
await auth.logout()
```

Other methods on the returned client: `forceRenew()` bypasses the
freshness check and renews immediately; `stepUp()` forces re-authentication
(`prompt=login`, `max_age=0`, `acr_values=mfa` by default) for a sensitive
operation that requires a fresh auth; `signDPoPProof(method, url)` signs a
standalone RFC 9449 proof for a request to your own protected resource;
`isDPoPActive()` reports whether DPoP is actually in effect (it can be
`false` even when `dpop: true` was requested, if WebCrypto is unavailable);
`destroy()` tears down timers and subscriptions.

## Lower-level primitives

The core also exports the building blocks for consumers who assemble their
own flows:

- **DPoP** - `createDPoPKeyManager` (per-tab non-exportable ES256 key,
  RFC 9449 proofs).
- **Verification** - `verifyIdToken` (JWKS signature + issuer + audience,
  the trust gate for cross-tab token adoption).
- **OIDC / PKCE** - `createUserManager`, `silentAuthorize`,
  `silentAuthorizeWithRetry`, `exchangeCode`, `refreshTokenGrant`,
  `revokeToken`.
- **Cross-tab** - `createTokenBroadcast`, `hasBroadcastSupport`,
  `withTabLock`, `hasTabLockSupport`.
- **Permissions** - `loadPermissions`, `permissionKey`.
- **Encryption** - `KEKVault`, `unwrapDEK`, `extractKEKFromFragment`,
  `kekBase64ToBytes`, `base64ToBytes` / `bytesToBase64Url` /
  `stringToBase64Url`.
- **Claims** - `parseAtolUser`, `decodeJWTPayload`, `getTokenExpiry`.

See the published type declarations (`dist/index.d.ts`) for the full
signatures; every export carries a doc comment.

## Security

This is a security library first. Key properties:

- **Memory-only tokens.** Access, ID, and (when opted in) refresh tokens
  live in an in-memory store and are never written to `localStorage` or
  `sessionStorage`. `sessionStorage` holds only the transient OIDC
  state/PKCE verifier needed to survive the login redirect. A page reload
  starts with an empty store; the client recovers by silently renewing
  against the IdP session cookie.
- **Iframe-default renewal, refresh required for cross-site.** By default
  the client renews in a hidden iframe against the IdP session cookie
  (`prompt=none`) and requests no refresh token, so there is no long-lived
  bearer credential to leak. The iframe path depends on the IdP session
  cookie being sent from a third-party context, which Safari ITP blocks
  outright and Chrome's third-party-cookie phase-out removes, so it fails
  **unconditionally** for a cross-site app -- one served on a different
  registrable domain than the IdP. Such apps therefore **must** set
  `useRefreshTokens: true`; that appends `offline_access` and renews via the
  refresh-token grant (memory-only, rotated, and DPoP-bound when `dpop` is
  on). Same-site apps (a console on a subdomain of the IdP) reach the
  first-party session cookie in the iframe and leave it `false`.
- **DPoP sender-constraint (RFC 9449).** When `dpop: true`, a per-tab,
  non-exportable ES256 keypair is generated on `init()` and a proof JWT is
  attached to every token-endpoint call and to `getAccessToken({ dpop })`
  results. A stolen access token cannot be replayed from another client
  without the private key, which never leaves the browser's WebCrypto
  keystore.
- **PKCE + nonce + ID token verification.** Login uses OIDC Authorization
  Code with PKCE (no implicit flow, no client secret in the browser).
  Cross-tab token adoption over `BroadcastChannel` is untrusted by default:
  a rotated token is only adopted after its ID token is verified against
  the issuer's JWKS (signature, issuer, audience) and the subject is
  pinned to the current session, so a same-origin script cannot forge a
  session takeover.
- **RP-initiated logout + refresh-token revocation.** `logout()`
  best-effort revokes the refresh token (RFC 7009) when one exists (the
  refresh opt-in) before redirecting to the issuer's `end_session` endpoint
  with `id_token_hint` and `post_logout_redirect_uri`, so the IdP session
  is torn down, not just the local one.

Found a vulnerability? See [SECURITY.md](./SECURITY.md) for how to report
it privately.

## Device intelligence (optional subpath)

```ts
import { DeviceCollector } from '@atol-sh/js/device'
```

The `@atol-sh/js/device` subpath is split out of the core barrel and
dynamic-imports `@atol-sh/fingerprint` (an optional peer dependency) so
consumers who don't use device intelligence never pull it into their
bundle. Install `@atol-sh/fingerprint` alongside `@atol-sh/js` to use it.

## Browser support

Requires a browser with WebCrypto (`crypto.subtle`): all evergreen
browsers (Chrome, Firefox, Safari, Edge) on both desktop and mobile.
When WebCrypto is unavailable (for example, a non-browser or non-secure
context), DPoP key generation returns `null` and the client falls back to
plain Bearer tokens automatically -- `isDPoPActive()` reports `false` and
no proof is attached, but authentication and token renewal continue to
work.

## Troubleshooting

- **Silent renew fails under Safari ITP, or any cross-site third-party-cookie
  blocking.** The default renewal model uses a hidden iframe against the
  IdP session cookie, which requires that cookie to be readable in a
  third-party context. Safari ITP blocks this outright, and Chrome's
  third-party-cookie phase-out removes it too. Fix: set
  `useRefreshTokens: true` so the client renews via the refresh-token grant
  instead.
- **"invalid redirect_uri".** The `redirectUri` you pass must be allow-listed
  for your publishable key in [console.atol.sh](https://console.atol.sh).
  Add the exact URI (scheme, host, port, path) there.
- **DPoP silently falls back to Bearer.** `dpop: true` only takes effect
  when WebCrypto is available; call `isDPoPActive()` to check whether it
  actually did. A server-issued `DPoP-Nonce` challenge is retried
  automatically with the nonce attached -- no consumer action needed.
- **Permission checks return `false` unexpectedly.** `loadPermissions`
  denies by default: a `false` means either the server-side permission
  genuinely isn't granted, or the bulk load itself failed (network error,
  shape mismatch) and the caller is expected to treat "unknown" the same as
  "denied".

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup, the test/coverage
gate, and the PR process. Please read [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
before participating.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for release notes.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
