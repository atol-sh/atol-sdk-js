# @atol-sh/js

[![npm version](https://img.shields.io/npm/v/@atol-sh/js.svg)](https://www.npmjs.com/package/@atol-sh/js)
[![CI](https://github.com/atol-sh/atol-sdk-js/actions/workflows/ci.yml/badge.svg)](https://github.com/atol-sh/atol-sdk-js/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@atol-sh/js.svg)](./LICENSE)

Framework-agnostic browser security core for [Atol](https://atol.sh): a
single config-driven client for OIDC authentication (Authorization Code +
PKCE), DPoP sender-constrained tokens (RFC 9449), silent renewal, cross-tab
coordination, and permission loading. `@atol-sh/react` is the React
binding, built as a thin wrapper over this same core.

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
  postLogoutRedirectUri: 'https://app.example.com/logout',
  dpop: true,                          // optional RFC 9449 sender-constrained tokens
  useRefreshTokens: false,             // default (same-site); REQUIRED true for cross-site apps
  storage: 'memory',                   // tokens are always memory-only
})

const unsubscribe = auth.onSessionChange(({ isAuthenticated, user, organizationId }) => {
  render(isAuthenticated, user, organizationId)
})

// On startup: handles a redirect callback, or silently restores a session
// from the IdP session cookie.
await auth.init()

// Start a login. returnTo is transaction-bound application state; it never
// changes the registered redirect URI. After verified credentials commit,
// the SDK restores it with same-origin history navigation.
await auth.beginLogin({ returnTo: '/dashboard' })

// On the redirect URI page: exchange the code for tokens. init() calls
// this automatically, so most apps never call it directly.
await auth.completeLogin()

// Switch the credential context after the user chooses an organization.
// This mints a new access/ID-token pair; it is not a generic token refresh.
await auth.selectOrganization('01KV4BNVVNZ4TNY0PP0CVXPZWP')

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

### Response-vault v1

Registered clients can opt into the public response-vault protocol when their
authorization server and same-origin relay support it:

```ts
const auth = createAtolBrowserAuth({
  issuer: 'https://id.example.com',
  clientId: 'example-spa',
  audience: 'https://api.example.com',
  scopes: 'openid profile email',
  redirectUri: 'https://app.example.com/callback',
  postLogoutRedirectUri: 'https://app.example.com/logout',
  dpop: { required: true },
  responseVault: true,
})
```

`responseVault: true` pushes authorization parameters in JSON request bodies,
navigates to a parameter-free `/auth/authorize`, and redeems the server-held
code through the same-origin client relay. Authorization codes, state, nonce,
PKCE material, request URIs, transaction IDs, and tokens never appear in a
navigation URL or `postMessage`. Every grant gets a fresh non-extractable DPoP
key, and tokens are validated before the one-use result is acknowledged.
Invalid or superseded grants are durably rejected, revoking any exact token
family relay already issued instead of leaving a server-side orphan.

The server publishes its v1 endpoints and registered binding in OIDC
discovery. A random PAR idempotency key makes an ambiguous push exactly
retryable, while a separate cancellation capability authorizes settlement
after mutable cookie and CSRF authority is cleared. Acknowledgement deletes
the delivery and enters a bounded `publishing` state; the SDK publishes
validated credentials locally, finalizes server adoption, then atomically
marks local custody `published` and releases its slot. Failure before that
last local transition rejects and revokes the exact family within the
compensation window.

Response-vault v1 requires a non-empty audience, mandatory DPoP, a clean
callback URL, and a distinct same-origin post-logout URL. It does not support
`deriveEncryptionKey`, whose URL-fragment delivery is incompatible with a
parameter-free callback. See [RESPONSE_VAULT_PROTOCOL.md](./RESPONSE_VAULT_PROTOCOL.md)
for the supported v1 contract.

Other methods on the returned client: `forceRenew()` bypasses the
freshness check and renews immediately; `stepUp()` forces re-authentication
(`prompt=login`, `max_age=0`, `acr_values=mfa` by default) for a sensitive
operation that requires a fresh auth; `selectOrganization(id)` starts a
distinct silent organization grant and exposes the selected ID on
`AtolSession.organizationId`; `signDPoPProof(method, url)` signs a
standalone RFC 9449 proof for a request to your own protected resource;
`isDPoPActive()` reports whether DPoP is actually in effect (it can be
`false` even when `dpop: true` was requested, if WebCrypto is unavailable);
`destroy()` tears down timers and subscriptions. If a browser resource close
throws, the client stays destroyed, retains only that cleanup ownership, and
throws `AtolBrowserAuthCleanupError`; calling `destroy()` again retries the
incomplete step.

## Lower-level primitives

The core also exports the building blocks for consumers who assemble their
own flows:

- **DPoP** - `createDPoPKeyManager` (per-tab non-exportable ES256 key,
  RFC 9449 proofs).
- **Verification** - `verifyIdToken` (JWKS signature + issuer + audience +
  required OIDC claims and callback nonce).
- **OIDC / PKCE** - `createUserManager`, `exchangeCode`,
  `refreshTokenGrant`, `revokeToken`. Browser authorization, including
  `prompt=none` iframe renewal, is admitted through durable ordinary PAR
  before navigation. Once `exchangeCode` dispatches the single-use code,
  transport loss or an incomplete response rejects with
  `AuthorizationCodeExchangeUncertainError` and code
  `authorization_code_exchange_uncertain`.
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
  `sessionStorage`. `sessionStorage` holds transient OIDC state/PKCE plus
  non-secret tab ownership and, in response-vault mode, one opaque active
  reference. `localStorage` holds only the non-secret credential generation
  and signed-out status. A page reload starts with an empty token store; the
  client recovers by silently renewing against the IdP session cookie unless
  durable local authority records that the application is signed out.
- **Ordinary redirect custody.** A DPoP authorization key staged before an
  ordinary full-page redirect remains in IndexedDB for the SDK's explicit
  15-minute browser-ceremony window plus the full 10-minute exchange lifetime
  of a code issued at that boundary. OIDC state cleanup and callback
  validation use the same checked 25-minute custody window; equality is
  expired. This is a fail-closed client custody policy, not authorization
  server authority. Response-vault mode instead has one server-enforced
  10-minute whole-transaction deadline and stores its key in that separate
  transaction record.
- **Ordinary authorization protocol v2.** Discovery must publish the nested v2
  PAR, pre-navigation cancellation, and settlement endpoints. The SDK sends
  one canonical credentialless form request, persists its cancellation
  capability before transport, and navigates with only `client_id` and the
  admitted `request_uri`. If it cannot durably adopt the PAR response, it
  resubmits the byte-identical form to the pre-navigation endpoint before
  removing custody. PAR responses require exact `application/json`, and
  settlement requests require exact `application/json`, both without
  media-type parameters. The SDK authenticates a cross-origin response only
  through the browser-visible `Atol-Browser-Authorization: v2` header. It does
  not use hidden CORS response headers as authority. Missing, unexposed,
  repeated, or unequal signals retain or settle custody and never authorize
  navigation or cleanup.
- **Response vault.** A response-vault client stores a bounded authorization
  transaction and non-extractable key handle in IndexedDB, with
  only an opaque same-tab reference in `sessionStorage`. One durable
  client-origin slot admits exactly one transaction across tabs and registered
  bindings. PAR and issuer-init use POST bodies; authorize and callback
  navigations are parameter-free. The same-origin relay supports exact
  redelivery after an ambiguous network loss. Capability acknowledgement
  deletes the delivery and opens bounded compensation, local publication
  installs validated credentials, and capability finalization confirms
  adoption. A crash that loses an acknowledged success rejects the exact
  unavailable family before obtaining one fresh silent grant; terminal errors
  retain and re-surface their exact classification. Bearer material is never
  persisted for recovery. Validation and authority failures enter an
  idempotently retryable rejection lineage that revokes and consumes the exact
  transaction, including a finalized transaction during the compensation
  window. Finalization reaches local `adopted`; `completePublication()`
  atomically changes it to `published` and releases the live origin slot.
  Ordinary crash scans compensate abandoned `adopted` custody and exclude
  clean `published` custody, while explicit logout includes both.
  Delivery-recovery routes remain private one-shot custody, and cleanup
  diagnostics retain no caught browser or transport errors. Active-custody
  recovery exposes only named binding, invalidation, busy, rejection, and
  cleanup diagnostics; unknown storage or WebCrypto values are discarded.
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
  keystore. Every token response is rejected unless `token_type=DPoP` and
  the access token's `cnf.jkt` matches that tab key. Use
  `dpop: { required: true }` to fail initialization when key creation is
  unavailable instead of permitting the boolean option's Bearer fallback.
- **PKCE + nonce + ID token verification.** Login uses OIDC Authorization
  Code with PKCE (no implicit flow, no client secret in the browser).
  Callback state and PKCE are consumed through oidc-client-ts, while the SDK
  performs the DPoP-aware code exchange and verifies the ID token against
  the issuer's JWKS, including the stored nonce when present.
- **Signal-only cross-tab coordination.** `BroadcastChannel` messages carry
  only credential-invalidation and session-ended signals. Access, ID, and
  refresh tokens never cross tabs; each receiving tab renews with its own
  DPoP key and grant.
- **Durable RP-initiated logout.** `logout()` atomically rotates the
  origin-wide credential generation into a non-secret signed-out tombstone
  before asynchronous teardown. It attempts refresh-token revocation
  (RFC 7009) and the issuer's `end_session` endpoint with a one-use callback
  state, and surfaces either failure. Reloads and tabs without
  `BroadcastChannel` remain signed out even if the IdP session cookie still
  exists. Failed attempts retain exact in-memory revocation and ID-token-hint
  custody for a same-runtime retry. Only an explicit `beginLogin()` clears
  the tombstone under a fresh generation.
- **Exact abandoned-login cancellation.** In response-vault mode,
  `cancelLogin()` is available only before client initialization on a
  signed-out browser. It claims and rejects the exact pending interactive
  generation, releases local custody, and never navigates to the issuer or
  ends an established session. Ambiguous rejection remains durable for an
  exact retry under an `interactive_cancel` provenance. Hidden-iframe renewal
  custody and generic lifecycle rejection can never satisfy that provenance.
  Damaged local key custody remains cancellable only when the durable source
  mode still proves that the transaction was interactive. Cleanup ownership is
  latched only after that durable cancellation claim succeeds. If rejection
  releases custody before tab-owner rotation is persisted, a same-runtime
  retry must replace and reread the retained local fence before it resolves.
  `beginLogin()` and `cancelLogin()` execute in call order, and every
  concurrent cancellation caller receives the same in-flight promise even if
  logout or another precondition changes while it runs. A same-tick logout
  therefore awaits an earlier queued cancellation; later cancellation
  requests are unavailable until logout finishes. Destroy cleanup is re-armed
  only after a later explicit login successfully establishes new interactive
  custody. Unsupported modes and initialized clients reject.

Found a vulnerability? See [SECURITY.md](./SECURITY.md) for how to report
it privately.

## Device intelligence (optional subpath)

```ts
import { DeviceCollector } from '@atol-sh/js/device'

const collector = new DeviceCollector('https://api.atol.sh', publishState)
await collector.collect({
  credentialGeneration: 1,
  authorize: async ({ method, url }) => {
    const credential = await auth.getAccessToken({ dpop: { method, url } })
    if (!credential) throw new Error('No authenticated session')
    return credential.proof
      ? {
          scheme: 'DPoP',
          accessToken: credential.token,
          dpopProof: credential.proof,
        }
      : { scheme: 'Bearer', accessToken: credential.token }
  },
})
```

The `@atol-sh/js/device` subpath is split out of the core barrel and
dynamic-imports `@atol-sh/fingerprint` (an optional peer dependency) so
consumers who don't use device intelligence never pull it into their
bundle. Install `@atol-sh/fingerprint` alongside `@atol-sh/js` to use it.
The collector validates the complete identify response before publishing
device state; malformed or drifted success payloads produce a closed error
and never receive invented defaults. Its operation-scoped credential owner
acquires the access token and DPoP proof atomically for the exact identify
URL; neither value is stored by the collector. Increment the non-secret
`credentialGeneration` whenever the session credential rotates. A newer
generation immediately fences late responses from every older request. Call
`collector.invalidate()` on logout before releasing the collector; future
credentials must continue with a higher generation.

## Browser support

Requires a browser with WebCrypto (`crypto.subtle`): all evergreen
browsers (Chrome, Firefox, Safari, Edge) on both desktop and mobile.
When WebCrypto is unavailable (for example, a non-browser or non-secure
context), DPoP key generation returns `null` and the client falls back to
plain Bearer tokens automatically -- `isDPoPActive()` reports `false` and
no proof is attached for ordinary clients. Response-vault mode never falls
back: missing WebCrypto is a fatal authorization error.

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
