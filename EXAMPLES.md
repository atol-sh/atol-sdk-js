# Examples

Runnable, framework-agnostic snippets for `@atol-sh/js`. Every symbol here
is checked against `src/index.ts` -- if it's not exported, it's not shown.

Building a React app? Use [`@atol-sh/react`](https://github.com/atol-sh/atol-sdk-react)
instead; these patterns still apply underneath.

## 1. Minimal login / logout

```ts
import { createAtolBrowserAuth } from '@atol-sh/js'

const auth = createAtolBrowserAuth({
  issuer: 'https://id.atol.sh',
  clientId: 'atol_kid_abc123', // from console.atol.sh
  redirectUri: 'https://app.example.com/callback',
})

// Subscribe before init() so you see the first snapshot too.
const unsubscribe = auth.onSessionChange(({ isAuthenticated, user }) => {
  if (isAuthenticated) {
    console.log('signed in as', user?.email)
  } else {
    console.log('signed out')
  }
})

// Call once at startup. On the redirect URI page this also completes the
// login (see completeLogin below); everywhere else it tries a silent
// restore against the IdP session cookie.
await auth.init()

// Wire a "Log in" button:
document.querySelector('#login')?.addEventListener('click', () => {
  void auth.beginLogin()
})

// Wire a "Log out" button:
document.querySelector('#logout')?.addEventListener('click', () => {
  void auth.logout()
})
```

On your redirect URI page, `init()` already calls `completeLogin()`
internally, so most apps never call it directly. If you need to complete
the exchange explicitly (for example, to await the result before
redirecting elsewhere in the app):

```ts
const session = await auth.completeLogin()
if (session.isAuthenticated) {
  window.location.assign('/dashboard')
}
```

Clean up on teardown (e.g. a single-page app tearing down a route):

```ts
unsubscribe()
auth.destroy()
```

## 2. Calling an API with `getAccessToken({ dpop })`

```ts
const auth = createAtolBrowserAuth({
  issuer: 'https://id.atol.sh',
  clientId: 'atol_kid_abc123',
  audience: 'https://api.example.com',
  redirectUri: 'https://app.example.com/callback',
  dpop: true, // RFC 9449 sender-constrained tokens
})

await auth.init()

async function fetchMe() {
  const url = 'https://api.example.com/me'
  const result = await auth.getAccessToken({ dpop: { method: 'GET', url } })
  if (!result) {
    throw new Error('not authenticated')
  }

  const headers: Record<string, string> = result.proof
    ? { Authorization: `DPoP ${result.token}`, DPoP: result.proof }
    : { Authorization: `Bearer ${result.token}` }

  const res = await fetch(url, { headers })
  return res.json()
}
```

`getAccessToken` renews under the hood when the token is within 60s of
expiry, so callers never need to check expiry themselves. If DPoP was
requested but WebCrypto wasn't available, `result.proof` is simply
`undefined` and you fall back to Bearer -- check `auth.isDPoPActive()` if
you need to know which mode is in effect ahead of time.

## 3. Refresh-token vs iframe renewal

Default (`useRefreshTokens: false`): renewal happens in a hidden iframe
against the IdP session cookie. No refresh token is requested or stored.
This only works for a **same-site** app (e.g. a console on a subdomain of
the issuer):

```ts
const auth = createAtolBrowserAuth({
  issuer: 'https://id.atol.sh',
  clientId: 'atol_kid_abc123',
  redirectUri: 'https://console.atol.sh/callback',
  // useRefreshTokens defaults to false: iframe renewal.
})
```

**Cross-site** apps (served on a different registrable domain than the
issuer) must opt into refresh tokens -- Safari ITP and Chrome's
third-party-cookie phase-out make the iframe path fail unconditionally:

```ts
const auth = createAtolBrowserAuth({
  issuer: 'https://id.atol.sh',
  clientId: 'atol_kid_abc123',
  redirectUri: 'https://app.example.com/callback',
  useRefreshTokens: true, // appends offline_access, renews via refresh grant
  useRefreshTokensFallback: true, // optional: fall back to iframe on a transient grant failure
})
```

Refresh tokens are still memory-only, rotated on every use, and
DPoP-bound when `dpop: true`. `logout()` best-effort revokes the refresh
token (RFC 7009) before redirecting to `end_session`.

You can also force an immediate renewal outside of the normal
expiry-driven schedule:

```ts
const newAccessToken = await auth.forceRenew()
```

## 4. Step-up re-auth with `stepUp()`

When a sensitive operation returns a `step_up_required` challenge (a fresh
authentication / second factor is needed), redirect through `stepUp()` and
retry the operation once the page comes back:

```ts
async function deleteOrg(orgId: string) {
  const result = await auth.getAccessToken()
  const res = await fetch(`/api/orgs/${orgId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${result?.token}` },
  })

  if (res.status === 403) {
    const body = await res.json()
    if (body.error === 'step_up_required') {
      // Redirects the browser; forces prompt=login, max_age=0, acr_values=mfa.
      await auth.stepUp({ returnTo: '/orgs' })
      return
    }
  }
  return res
}
```

Override the assurance level or accept a very recent login instead of
forcing a brand-new one:

```ts
await auth.stepUp({ returnTo: '/billing', maxAge: 300, acrValues: 'mfa' })
```

## 5. Permission checks

```ts
import { createAtolBrowserAuth, loadPermissions, permissionKey } from '@atol-sh/js'

const auth = createAtolBrowserAuth({
  issuer: 'https://id.atol.sh',
  clientId: 'atol_kid_abc123',
  redirectUri: 'https://app.example.com/callback',
  dpop: true,
})

await auth.init()

async function checkPermissions() {
  const result = await auth.getAccessToken()
  if (!result) return new Map<string, boolean>()

  const user = /* the AtolUser from onSessionChange / session state */ null
  if (!user) return new Map<string, boolean>()

  return loadPermissions({
    apiUrl: 'https://api.atol.sh', // control-plane API host, NOT the issuer
    keyId: 'atol_kid_abc123',
    accessToken: result.token,
    userId: user.id,
    orgId: user.orgId,
    checks: [
      { action: 'edit', resource: 'publication' },
      { action: 'manage', resource: 'team:team-123' },
    ],
    // Pass a DPoP signer when the session is DPoP-bound so the resource
    // server sees `DPoP` + a matching proof instead of a stolen-looking
    // Bearer token. signDPoPProof() re-fetches the token itself, so this
    // adapter only needs to forward the (method, url) pair.
    dpop: auth.isDPoPActive()
      ? {
          signProof: async (method: string, url: string) => {
            const r = await auth.signDPoPProof(method, url)
            if (!r?.proof) throw new Error('DPoP proof unavailable')
            return r.proof
          },
        }
      : undefined,
  })
}

const permissions = await checkPermissions()
const canEdit = permissions.get(permissionKey('edit', 'publication')) === true
```

`loadPermissions` denies by default: a missing check, a malformed
response, or a shape mismatch between requested checks and returned
results throws rather than silently returning `true` for anything.
Treat a thrown error the same as "no permissions granted" in your UI.

## 6. Device intelligence (`./device` subpath)

Optional, and only pulls in `@atol-sh/fingerprint` (an optional peer
dependency) when you actually import this subpath:

```bash
npm install @atol-sh/js @atol-sh/fingerprint
```

```ts
import { DeviceCollector, DEFAULT_DEVICE_API_URL } from '@atol-sh/js/device'

const collector = new DeviceCollector(DEFAULT_DEVICE_API_URL, (state) => {
  if (state.loading) return
  if (state.error) {
    console.error('device intelligence failed', state.error)
    return
  }
  console.log('device', state.deviceId, 'known:', state.known, 'signals:', state.signals)
})

// Collect once you have an access token (or call with no token to just
// pre-load the fingerprint agent):
const result = await auth.getAccessToken()
if (result) {
  await collector.collect(result.token)
}
```

`DeviceCollector` is framework-agnostic: it dedupes concurrent `collect()`
calls for the same token and reloads the underlying agent if the API host
changes. A framework binding (like `@atol-sh/react`'s device hook) wraps
this in reactive state; you can drive it directly with plain callbacks as
shown above.
