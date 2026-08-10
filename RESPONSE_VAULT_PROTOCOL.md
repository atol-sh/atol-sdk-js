# Response-vault browser authorization protocol v1

Response-vault v1 is a public Atol browser authorization profile. It combines
an exact JSON pushed request, parameter-free navigation, a same-origin
one-use relay, DPoP-bound issuance, capability settlement, and durable state
machines. Authorization responses stay out of navigation URLs, form posts,
`postMessage`, and browser-persisted bearer-token storage.

The words MUST, MUST NOT, SHOULD, and MAY describe requirements for an
interoperable v1 implementation.

## Enabling the profile

The public SDK enables the profile with `responseVault: true`:

```ts
const auth = createAtolBrowserAuth({
  issuer: 'https://id.example.com',
  clientId: 'example-spa',
  audience: 'https://api.example.com',
  scopes: 'openid profile email',
  redirectUri: 'https://app.example.com/oidc/complete',
  postLogoutRedirectUri: 'https://app.example.com/logout',
  dpop: { required: true },
  responseVault: true,
})
```

Enabling the SDK option does not add server support. The issuer and the
client-origin service MUST implement the same v1 contract for the registered
client.

The registration and SDK configuration have these requirements:

- `issuer` is an HTTPS origin. HTTP is accepted only for loopback development,
  and its scheme MUST match the redirect scheme.
- `redirectUri` is an exact secure-context URL without credentials, query, or
  fragment. `client origin` means its origin.
- `postLogoutRedirectUri` is a distinct, clean absolute URL on the client
  origin.
- `clientId` and `audience` are non-empty registered values.
- `scopes` is a canonical, space-delimited list with no duplicates and MUST
  contain `openid`.
- DPoP is mandatory. Every authorization uses a fresh, non-extractable P-256
  key.
- `deriveEncryptionKey` is unsupported because fragment delivery is
  incompatible with a parameter-free callback.

## Discovery

An issuer that supports this profile advertises `atol_console_vault` in
`response_modes_supported` and publishes this exact metadata member:

```json
{
  "atol_console_browser_authorization": {
    "version": 1,
    "response_mode": "atol_console_vault",
    "client_id": "example-spa",
    "redirect_uri": "https://app.example.com/oidc/complete",
    "audience": "https://api.example.com",
    "console_origin": "https://app.example.com",
    "bootstrap_endpoint": "https://app.example.com/auth/browser/v1/bootstrap",
    "pushed_authorization_request_endpoint": "https://app.example.com/auth/browser/v1/pushed-authorization-requests",
    "issuer_bootstrap_endpoint": "https://id.example.com/auth/browser/v1/issuer-bootstrap",
    "authorization_init_endpoint": "https://id.example.com/auth/browser/v1/authorization-init",
    "authorization_endpoint": "https://id.example.com/auth/authorize",
    "relay_endpoint": "https://app.example.com/auth/browser/v1/relay",
    "acknowledgement_endpoint": "https://app.example.com/auth/browser/v1/acknowledge",
    "finalization_endpoint": "https://app.example.com/auth/browser/v1/finalize",
    "rejection_endpoint": "https://app.example.com/auth/browser/v1/reject"
  }
}
```

The metadata member and `console_origin` name are fixed v1 wire names. They do
not restrict the public SDK profile to one application.

All values are registration authority. The client ID, redirect URI, audience,
client origin, issuer origin, response mode, version, and endpoint origins
MUST agree. A client MUST NOT derive authority from an unregistered discovery
value or silently fall back to query, fragment, form-post, or `web_message`.
An issuer MUST fail discovery rather than advertise stale or partially
available response-vault metadata.

The standard top-level discovery members are part of the same binding:

- `issuer` MUST equal the normalized configured issuer;
- `authorization_endpoint` MUST equal both the custom
  `authorization_endpoint` and `${issuer}/auth/authorize`; and
- `token_endpoint` MUST equal `${issuer}/auth/token`, the exact `htu` used for
  the relay DPoP proof.

Missing, duplicated, or conflicting discovery authority is terminal. The SDK
does not cache a failed discovery result.

## Common wire rules

All JSON protocol endpoints use `POST`. The initial authorization navigation
uses `GET`; issuer interaction may use document `POST`. Every JSON request
contains `"version": 1`. JSON objects:

- MUST use `Content-Type: application/json` without media-type parameters;
- MUST be no larger than 16 KiB at the service boundary;
- MUST contain exactly the defined members;
- MUST reject unknown or duplicate members; and
- MUST reject trailing JSON values.

A canonical 43-character value is the unpadded base64url encoding of 32
bytes and matches `^[A-Za-z0-9_-]{43}$`. Secrets and IDs use random bytes;
S256 challenges and DPoP JWK thumbprints use 32-byte digests.

JSON responses use `Content-Type: application/json`. Empty `204` responses
MUST have no body. Every response is non-cacheable. The SDK sends protocol
requests with `cache: "no-store"`, `redirect: "error"`, and
`referrerPolicy: "no-referrer"`.

The service accepts request bodies up to 16 KiB. The SDK consumes response
bodies as a stream and rejects an invalid `Content-Length`, invalid UTF-8, or
more than 32 KiB before parsing the envelope. The operation deadline covers
both response headers and complete body consumption.

### Browser boundary

Client-origin endpoints require an exact same-origin credentialed fetch with
the client `Origin`, `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: cors`,
and `Sec-Fetch-Dest: empty`.

Issuer bootstrap and authorization-init are credentialed CORS requests from
the registered client origin. They require `Sec-Fetch-Site: same-site` and an
exact preflight. The issuer allows only `POST`, credentials, and the precise
headers needed by the endpoint. It does not reflect arbitrary origins.

The initial authorization navigation is a same-site document or iframe
navigation to the exact parameter-free authorization endpoint. The callback
is the exact registered redirect path with no query or fragment.

### Error envelopes

A protocol denial has exactly one member:

```json
{ "error": "invalid_request" }
```

The allowed protocol codes are:

| Code                        | Meaning                                                                  |
| --------------------------- | ------------------------------------------------------------------------ |
| `invalid_request`           | Malformed, expired, consumed, substituted, or invalid state              |
| `forbidden`                 | Origin, Fetch Metadata, cookie, or CSRF browser boundary failed          |
| `busy`                      | A live bootstrap or browser authority already owns the supplied boundary |
| `unavailable`               | Required durable state or another required dependency is unavailable     |
| `authorization_nonterminal` | Exact authenticated custody remains live; retain it                      |
| `authorization_terminal`    | Exact authenticated custody is terminal; deletion is permitted           |

The envelope is intentionally unversioned. Missing and substituted authority
are not distinguishable to the caller. `authorization_nonterminal` and
`authorization_terminal` are cleanup authority only when the exact endpoint,
status, content type, no-store policy, body, and caller-held capability binding
all authenticate. A generic or malformed 409/410 never authorizes deletion.

A stored terminal authorization result is different. It is a versioned,
redeliverable relay envelope:

```json
{
  "version": 1,
  "error": "access_denied",
  "csrf_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

Its `error` is exactly one of `invalid_request`, `access_denied`,
`login_required`, `temporarily_unavailable`, or `server_error`.

A DPoP denial is also distinct:

```json
{
  "error": "use_dpop_nonce",
  "error_description": "authorization server requires a nonce in the DPoP proof"
}
```

`use_dpop_nonce` has the exact description shown above and includes exactly
one `DPoP-Nonce` response header. `invalid_dpop_proof` has description
`the DPoP proof is invalid` and no nonce. A nonce is 1 through 512 RFC 6749
NQCHAR characters; comma, whitespace, controls, and duplicate comma-joined
fields are invalid. A DPoP envelope has exactly `error` and
`error_description`; it is not a stored terminal authorization result.

## Endpoints and exact schemas

`client origin` is the origin of the registered redirect URI. The exact
endpoint URLs are the discovery values above.

### Bootstrap

Before client-origin bootstrap, the SDK persists one `prepared` record with
the exact tab, cancellation, and PAR-idempotency capabilities. The
client-origin endpoint accepts:

```json
{
  "version": 1,
  "mode": "create",
  "tab_secret": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "cancellation_secret": "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
  "par_idempotency_key": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
}
```

`mode` is exactly `create` or `terminal_only`. Both modes reuse the same
persisted capabilities. They send no CSRF header and may carry the HttpOnly
cookie from an earlier exact attempt.

`create` success is `201`:

```json
{
  "version": 1,
  "csrf_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "expires_in": 60,
  "bootstrap_terminal_proof": "opaque-server-proof"
}
```

The server encrypts the generated cookie and CSRF response and binds it to the
capabilities, original presented cookie, committed cookie, immutable database
deadline, and selected terminal-proof key identity. An exact retry accepts
either the original cookie state or the committed cookie. It returns the same
cookie, CSRF, proof identity, and deadline with decreasing `expires_in`; it
does not regenerate authority or extend the deadline. A different binding
under the same idempotency capability is `400 invalid_request`.

`terminal_only` never creates live authority. It returns exact no-store
`409 {"error":"authorization_nonterminal"}` for an exact live row and exact
no-store `410 {"error":"authorization_terminal"}` for terminal state. If the
original create never committed, the server atomically installs the exact
capability-bound terminal fence before returning 410. A delayed create cannot
resurrect that attempt. Only an authenticated exact 410 permits local
deletion. An exact 409, a generic error, a malformed response, or an
unauthenticated 410 preserves prepared custody.

The issuer bootstrap endpoint remains separate and accepts only:

```json
{ "version": 1 }
```

Its `201` response has `version`, `csrf_token`, and `expires_in`; it does not
return a terminal proof and is not part of client-origin prepared recovery.

The client-origin cookie is `__Host-atol-console-bff`; the issuer cookie is
`__Host-atol-issuer-init`. Both are host-only, `Path=/`, `Secure`, `HttpOnly`,
`SameSite=Strict`, and have a 60-second bootstrap lifetime. CSRF is returned
only in JSON. PAR, authorization-init, and relay send it once as
`X-Atol-CSRF`; bootstrap and capability settlement send no CSRF header.

Client-origin bootstrap errors are `400 invalid_request`, `403 forbidden`,
`409 busy`, exact authenticated `409 authorization_nonterminal`, exact
authenticated `410 authorization_terminal`, or `503 unavailable`. Issuer
bootstrap errors are `400 invalid_request`, `403 forbidden`, `409 busy`, or
`503 unavailable`.

### Pushed authorization request

The client-origin pushed request has this exact shape:

```json
{
  "version": 1,
  "client_id": "example-spa",
  "redirect_uri": "https://app.example.com/oidc/complete",
  "response_type": "code",
  "scope": "openid profile email",
  "state": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "nonce": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  "code_challenge": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
  "code_challenge_method": "S256",
  "dpop_jkt": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
  "audience": "https://api.example.com",
  "tab_secret": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "par_idempotency_key": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  "cancellation_secret": "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
  "bootstrap_terminal_proof": "opaque-server-proof"
}
```

The only optional members are:

```json
{
  "prompt": "login",
  "max_age": 0,
  "acr_values": "mfa",
  "organization_id": "01KV4BNVVNZ4TNY0PP0CVXPZWP"
}
```

`prompt`, when present, is `login` or `none`. `max_age` is an integer from 0
through 86400. `scope` has one through four unique values from `openid`,
`profile`, `email`, and `offline_access`, separated by one ASCII space;
`openid` is required. `acr_values` is `mfa` or `urn:atol:acr:mfa`.
`organization_id`, when supported by the registration, is a canonical ULID.
`audience` is the exact value from discovery.

Success is `201`:

```json
{
  "version": 1,
  "transaction_id": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
  "request_uri": "urn:ietf:params:oauth:request_uri:IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",
  "expires_in": 60,
  "transaction_expires_in": 600,
  "csrf_token": "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ",
  "terminal_proof": "opaque-server-proof"
}
```

The service consumes the bootstrap and rotates both the client-origin cookie
and CSRF token. The replacement cookie is valid for the bounded transaction,
which is at most ten minutes.

Bootstrap `expires_in` is the database-observed remaining bootstrap lifetime
from 1 through 60 seconds. PAR `expires_in` is the remaining request-URI
lifetime from 0 through 60 seconds; zero is returned only when an exact replay
finds a transaction whose request URI can no longer be used.
`transaction_expires_in` is the independently remaining transaction lifetime
from 1 through 600 seconds. Equality is expired.

The SDK creates `par_idempotency_key`, `cancellation_secret`, and
`tab_secret` before its first PAR attempt and persists them before transport.
The service stores digests of those capabilities, not their plaintext. The
bootstrap proof binds the original bootstrap cookie, CSRF, capabilities,
client origin, client ID, persisted proof-key identity, and maximum possible
transaction deadline. The transaction proof binds the exact transaction,
client, tab, cancellation capability, persisted proof-key identity, and
original transaction deadline.

An exact PAR retry MUST compare the idempotency key, canonical authorization
parameters, tab secret, cancellation secret, client registration, response
mode, and protocol version. During an ambiguous response it accepts the
original or replacement cookie and the original or replacement CSRF binding.
It returns the same transaction ID, request URI, replacement cookie, CSRF,
and original absolute request-URI and transaction deadlines. Remaining
intervals decrease from those deadlines; replay never refreshes either one.
Recovery runs before mutable client-registration admission, Fosite, database
clock reads, random generation, or envelope sealing. It MUST NOT create
another transaction or repeat secret generation. A changed request under the
same idempotency key is `400 invalid_request`.

Proof recovery uses the proof-key identity persisted with the exact row, not
the key active at retry time. The server retains referenced predecessor keys
through the bounded recovery window. A missing referenced key is
`503 unavailable`; the server MUST NOT substitute a different key.

PAR errors are `400 invalid_request`, `403 forbidden`, or `503 unavailable`.

### Issuer initialization

After issuer bootstrap, authorization-init accepts:

```json
{
  "version": 1,
  "request_uri": "urn:ietf:params:oauth:request_uri:IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"
}
```

It requires the issuer cookie and issuer-bootstrap CSRF header. Success is an
empty `204`. It consumes the issuer bootstrap, replaces it with an
issuer-transaction cookie, and binds that cookie to exactly one live request
URI and issuer authority for at most ten minutes.

Errors are `400 invalid_request`, `403 forbidden`, or `503 unavailable`.

### Authorization navigation

The browser navigates to `/auth/authorize` with no query or fragment. The
issuer loads all OAuth parameters from the server-held request and validates
the exact registered client, redirect URI, response type, scope, audience,
PKCE challenge, DPoP JKT, state, nonce, and optional intent.

The successful or terminal result is encrypted in the server response vault.
The issuer returns `303` to the exact clean callback and expires the
issuer-transaction cookie. It never puts code, state, error, or other
authorization data in the redirect.

### Relay

Relay requires the client-origin transaction cookie and current CSRF header:

```json
{
  "version": 1,
  "transaction_id": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
  "tab_secret": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "code_verifier": "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
  "dpop_proof": "compact-jws"
}
```

The verifier is 43 through 128 RFC 7636 unreserved characters. The compact
DPoP proof is at most 12 KiB and is for `POST` to the issuer token endpoint.

Success is `200` with exactly the required members and optional token members:

```json
{
  "version": 1,
  "access_token": "access-token",
  "token_type": "DPoP",
  "expires_in": 3600,
  "refresh_token": "optional-refresh-token",
  "id_token": "optional-id-token",
  "scope": "openid profile email",
  "csrf_token": "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL"
}
```

`access_token`, `token_type`, `expires_in`, `scope`, and `csrf_token` are
required. `refresh_token` and `id_token` are optional. The SDK accepts an
expiry from 1 through 86400 seconds, a scope up to 512 characters, and each
token up to 32 KiB, subject to the 32 KiB total response limit.
A success may include one valid `DPoP-Nonce` header for the next proof.

The first valid relay atomically:

1. validates the cookie, CSRF, transaction, tab, PAR, PKCE, DPoP JKT, issuer,
   and live login-session fence;
2. exchanges a success code once or classifies the stored terminal error;
3. replaces the authorization vault with a separately encrypted exact
   delivery envelope;
4. rotates CSRF and retains the prior CSRF only for exact relay recovery; and
5. enters `issued` for success or `failed` for a terminal error.

An exact redelivery accepts the same cookie, transaction, tab secret, and
either the pre-delivery or rotated CSRF. It decrypts the existing delivery
and returns byte-equivalent JSON semantics. It does not reuse the code, mint
another token family, rotate CSRF again, or change session authority.
The server performs this terminal delivery recovery before consulting mutable
issuer status or client registration. Suspension or a later registration
change may deny a nonterminal token issuance, but cannot strand an already
committed `issued` or `failed` delivery.

A valid `use_dpop_nonce` challenge leaves the transaction unchanged. The SDK
retries once with the same transaction and DPoP key plus the nonce. A malformed
or repeated challenge is rejected and the transaction is settled through the
rejection endpoint.

Relay errors are:

- `400` for a stored terminal envelope, a DPoP envelope, or unversioned
  `invalid_request`;
- `403 forbidden` for the browser boundary; and
- `503 unavailable` for retryable transaction or dependency failure.

### Acknowledge, finalize, and reject

Acknowledge and finalize use the same exact capability body:

```json
{
  "version": 1,
  "transaction_id": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
  "tab_secret": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "cancellation_secret": "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
}
```

They are exact same-origin fetches, but the settlement authority is the
transaction, tab, and cancellation capability. They do not require a cookie
or CSRF header.

`/acknowledge` changes `issued` or `failed` to `publishing`. The first commit:

- deletes the encrypted delivery;
- clears cookie, CSRF, issuer-cookie, PAR, and relay-recovery authority;
- records acknowledgement using database time;
- retains the cancellation capability until the original transaction expiry;
  and
- expires any client-origin transaction cookie in the `204` response.

An exact acknowledgement retry in `publishing` or `adopted` returns the same
empty `204`.

`/finalize` changes `publishing` to `adopted`. It is valid only before the
transaction expires. An exact retry of an adopted transaction returns the same
empty `204`.

`/reject` is the monotonic compensation and terminal-classification path. A
mutating rejection adds the required mode:

```json
{
  "version": 1,
  "mode": "reject",
  "transaction_id": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
  "tab_secret": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "cancellation_secret": "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
}
```

`reject` accepts an exact live
transaction in `pushed`, `ready`, `vault`, `issued`, `failed`, or `publishing`.
It also accepts `adopted` only before the original transaction expiry. Its
transaction:

- revokes every token artifact in the exact issued request family;
- deletes every encrypted authorization or delivery vault;
- clears all mutable cookie, CSRF, PAR, and relay authority;
- records rejection using database time; and
- expires any client-origin transaction cookie and enters `rejected`.

An exact retry of a rejected tombstone returns the same empty `204`.
Finalization and rejection serialize on the same transaction. Once rejection
wins, finalization cannot resurrect the grant.

Cleanup driven only by a local deadline uses:

```json
{
  "version": 1,
  "mode": "terminal_only",
  "client_id": "example-spa",
  "transaction_id": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
  "tab_secret": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "cancellation_secret": "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
  "terminal_proof": "opaque-server-proof"
}
```

`terminal_only` never mutates a live transaction. It returns exact no-store
409 `authorization_nonterminal` while the database row remains live and exact
no-store 410 `authorization_terminal` only after database-clock expiry,
terminal transition, and the token-family invariant. After bounded tombstone
collection, the signed proof and database clock can authenticate absence as
terminal at or after the original deadline. Before that deadline, or when the
database clock or referenced proof key is unavailable, the server returns 503. Missing or substituted authority is generic 400. Realm suspension and
client-registration changes do not block either settlement mode because they
authenticate retained authority rather than admitting a new grant.

Settlement errors are `400 invalid_request`, `403 forbidden`, exact
`409 authorization_nonterminal`, exact `410 authorization_terminal`, or
`503 unavailable`. A `204` always has an empty body.

## Server state machine

| State        | Durable meaning                                                       | Next valid transitions                              |
| ------------ | --------------------------------------------------------------------- | --------------------------------------------------- |
| bootstrap    | Exact encrypted cookie/CSRF response or terminal fence                | `pushed`, consumed, or terminal                     |
| `pushed`     | Exact encrypted PAR and cancellation binding exist                    | `ready`, `rejected`, or `expired`                   |
| `ready`      | Issuer cookie is bound to the PAR                                     | `vault`, `rejected`, or `expired`                   |
| `vault`      | Encrypted code or terminal authorization result exists                | `issued`, `failed`, `rejected`, or `expired`        |
| `issued`     | One token family and exact encrypted delivery exist                   | `publishing`, `rejected`, or `expired`              |
| `failed`     | Exact encrypted terminal error delivery exists                        | `publishing`, `rejected`, or `expired`              |
| `publishing` | Delivery and mutable browser authority are gone; compensation is open | `adopted`, `rejected`, or `expired`                 |
| `adopted`    | Publication was finalized                                             | exact retry, bounded `rejected`, or terminal expiry |
| `rejected`   | Exact family is revoked and mutable authority is gone                 | exact retry or terminal expiry                      |
| `expired`    | No live transaction authority remains                                 | none                                                |

All expiry comparisons use database time. Equality is expired.
Consumed and terminal bootstrap and transaction fences are retained for a
bounded 24-hour exact-retry window after the immutable deadline. Reaping
clears encrypted response material and all mutable cookie authority before
deleting the non-authority fence in bounded batches.

An expired `issued` or `publishing` transaction MUST have its exact token
family revoked before cleanup. Reaping a rejected token family re-verifies
that no live family remains. An adopted transaction is never revoked by the
expiry reaper. At transaction expiry, adopted rejection is denied.

## Browser custody and authority

The SDK maintains one host-wide response-vault slot per client origin. The
slot is shared across tabs and across response-vault configurations on that
origin. IndexedDB compare-and-set admits exactly one unexpired owner before
any server request. A competing start receives
`ResponseVaultAuthorizationBusyError`; it does not create a second PAR.

The durable record contains the registered binding, authorization intent,
random protocol secrets, settlement classification, generation snapshot, and
non-extractable DPoP `CryptoKey` handles. Access, refresh, and ID tokens are
never persisted. Beyond ordinary OIDC state and the non-secret tab generation,
response-vault mode adds only one opaque record reference to `sessionStorage`.
Before PAR, the live record and slot use the remaining 60-second bootstrap
deadline. A successful PAR atomically replaces both with the original
ten-minute transaction deadline. Clean publication uses one IndexedDB
transaction to release the slot and replace full grant custody with an exact,
whitelist-built `published` cancellation-only record. That record retains only
the registered binding, generation snapshot, transaction and cancellation
capabilities, original deadline, execution fence, and a closed rejection
provenance; it cannot resume a grant. Ordinary protocol and lifecycle
rejection use `internal`. Only an atomic claim of a stored `interactive`
authorization may write `interactive_cancel`.

`prepared` is not locally reapable once bootstrap transport begins because
the server may have committed `create` before its response was lost. Network
failure, malformed response, generic protocol denial, lifecycle invalidation,
and generation mismatch preserve the record and release only its fenced
execution claim. While its phase is live, a later owner retries exact
`create`. At local equality or expiry, it sends exact `terminal_only`. Only an
authenticated 410 deletes the record; authenticated 409 and every
unauthenticated or malformed result retain it.

A brand-new start resolves and validates immutable discovery authority before
staging `prepared`. Failure at that preflight leaves no custody because no
bootstrap request could have been sent. Recovery of an existing prepared
owner does not gain that proof of absence, so discovery failure preserves it.

Every side-effecting browser operation holds a random execution owner, a
monotonically increasing fence, and a bounded lease. Every mutation, release,
and delete must present the exact owner and fence. An expired lease can be
taken over, but the stale handle cannot mutate custody afterward.

Navigation is separate from execution. Immediately before interactive or
iframe navigation, the SDK persists `navigating`, a random navigation owner,
and an absolute deadline, then releases the execution lease. Only a callback
holding that exact navigation owner may atomically enter `redeeming`.
Long-running external login or MFA therefore does not depend on renewing a
short execution lease, and another live SDK instance reports busy rather than
rejecting peer authority.

Two independent, random 32-byte generations fence asynchronous work:

- the credential-authority generation is origin-wide for an exact issuer,
  client, and client origin and is stored with `active` or `signed_out` status
  in one canonical `localStorage` record; and
- the tab-owner generation survives a redirect in `sessionStorage` and is
  scoped to the issuer, client, and redirect URI.

They are random values, not counters. A missing authority record is initialized
as active with fresh randomness and reread so a concurrent persisted writer
wins. Logout atomically writes a fresh generation and `signed_out` tombstone
before asynchronous teardown, then replaces the tab-owner generation. Client
destruction replaces only the tab-owner generation. Invalidation replacement
never parses the old value, so corrupt storage cannot preserve stale authority.
Every assertion rejects `signed_out` authority even when its generation
matches.

Cold startup under `signed_out` authority runs application-scoped lifecycle
cleanup, including superseded `adopted` and clean `published` custody, without
rotating the shared authority again. It then suppresses silent authorization
even when the IdP session cookie remains live. This remains correct when
`BroadcastChannel` is absent or delayed. Only explicit login atomically
installs a fresh active generation; a stale cleanup cannot overwrite it.

Every ordinary and response-vault authorization snapshots both generations.
The SDK checks the snapshot before and after asynchronous proof generation,
relay, validation, credential publication, and settlement. A stale operation
cannot commit credentials. Rejection deliberately retains its exact
cancellation capability after generation rotation so logout can still revoke
server authority. RP-initiated logout uses one-use validated callback state,
surfaces revocation or navigation failures, and retains exact in-memory retry
custody for the current runtime.

`cancelLogin()` is the non-navigating cancellation boundary for an abandoned
interactive response-vault authorization. It is valid only on an
uninitialized, signed-out response-vault client. The SDK claims durable
`interactive_cancel` rejection provenance before replacing the tab-owner
generation, cancels owned work, rejects the exact active transaction, and
resolves only after local custody release. The atomic claim verifies the
stored mode is `interactive`; iframe renewal and internally rejected custody
cannot be relabeled or cancelled through this API. An ambiguous rejection
remains `rejecting` or `reject_retry` in the single active slot, so the same or
a fresh client may resume only that terminal operation with a fresh custody
revision and held Web Lock; a stale process-local handle cannot win. A
same-runtime cancellation retains its pre-rotation tab-owner fence if local
rotation fails after rejection has already released durable custody. A
custody-free retry replaces that fence and rereads `sessionStorage` to prove
the stale owner is gone before it may resolve. A
damaged full grant may fall back to cancellation custody only when its durable
source mode still proves `interactive`; missing key material never permits an
iframe grant or unproven record to acquire interactive cancellation
provenance. Destroy-cleanup ownership is latched only after the durable claim,
so a pre-claim absence, contention, or validation failure cannot suppress
later lifecycle invalidation. A
client-local FIFO orders `beginLogin()` and `cancelLogin()`, so cancellation
cannot resolve before an earlier yielding login has either navigated or
failed. The first cancellation promise remains the single-flight identity
before logout and mutable preconditions are rechecked. A logout admitted after
that queued cancellation awaits the exact promise instead of retroactively
invalidating it; a cancellation requested after logout starts is unavailable.
The operation does not write a signed-out logout tombstone, call `end_session`,
or expose transaction capabilities. Completed cancellation suppresses
duplicate destroy cleanup until a later explicit `beginLogin()` successfully
establishes new interactive custody. `logout()` awaits an in-flight
cancellation and propagates its failure.

## Browser durable states

| State            | Meaning after a crash or reload                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| `prepared`       | Local capabilities exist; bootstrap create may have committed and must be exactly retried or terminally classified |
| `par_pending`    | Bootstrap CSRF and exact PAR retry material are durable                                                            |
| `pushed`         | Transaction ID, request URI, rotated CSRF, and cancellation capability are durable                                 |
| `initializing`   | Issuer initialization may have committed; a crash must exact-reject rather than replay mutable initialization      |
| `initialized`    | Issuer initialization committed; callback may relay                                                                |
| `navigating`     | Browser navigation owns the transaction until its persisted callback deadline                                      |
| `redeeming`      | A relay may have reached the service                                                                               |
| `relay_retry`    | Retry the exact relay; do not start another grant                                                                  |
| `awaiting_ack`   | Parsed result classification and rotated CSRF are durable; bearer material is memory-only                          |
| `publishing`     | Acknowledgement committed; local credential publication must finish or compensate                                  |
| `finalizing`     | Finalization may have committed and is exactly retryable                                                           |
| `adopted`        | Finalization is confirmed, but local publication and slot release are not confirmed; ordinary recovery compensates |
| `published`      | Local publication and slot release are confirmed; only explicit lifecycle invalidation or logout may cancel        |
| `rejecting`      | Rejection intent and closed provenance were persisted before transport                                              |
| `reject_retry`   | Rejection outcome is ambiguous; retry the same capability and provenance                                              |
| `reject_blocked` | An authoritative rejection denial occurred; retain custody and do not invent cleanup                               |

State changes and the host-wide slot update in one IndexedDB transaction.
A page crash in an in-flight state is recovered into the corresponding exact
retry state. Corrupt, mismatched, or expired custody fails closed.

## Publication and compensation

A relayed success is not immediately live:

1. The SDK parses the exact envelope and validates token type, issuer,
   audience, subject, OIDC nonce, organization context, and `cnf.jkt`.
2. The SDK prepares local credential and encryption state without publishing
   it.
3. Capability acknowledgement moves the server to `publishing` and deletes
   the redeliverable delivery.
4. The SDK atomically publishes the prepared credentials under the same
   lifecycle and generation fences.
5. Capability finalization moves the server to `adopted`.
6. The SDK atomically replaces `adopted` grant custody with the exact
   whitelist-built `published` cancellation-only record, releases the
   host-wide slot, and retains that cancellation capability until expiry.

A fresh SDK instance for the same binding and tab owner treats retained
`adopted` custody as abandoned and rejects it before recovery. Ordinary crash
compensation excludes `published`. Explicit lifecycle invalidation and logout
include it. Cleanup inventory uses a durable primary-key continuation and
visits at most 64 records per invocation. Repeated invocations advance through
unrelated and owned custody without materializing the database, and wrap after
reaching the end. The loader returns a two-phase continuation: the caller
commits it with a compare-and-swap only after every returned custody operation
succeeds. Parse, rejection, and cleanup failures leave the cursor unchanged so
the exact custody is retried. A malformed cancellation candidate therefore
fails closed without being skipped, while scanning never deletes live custody.

Rejection uses only the stored binding and client origin, transaction ID, tab
secret, cancellation secret, deadline, and execution fence. It derives the
fixed same-origin version-1 rejection path and does not require issuer
discovery, rotated CSRF, or a usable DPoP private key. Grant resume and relay
still require and thumbprint-validate the non-extractable DPoP key.

If anything fails after acknowledgement but before complete local cleanup,
the SDK clears locally published credentials and rejects the exact
transaction before its original expiry. This includes an ambiguous
finalization or local durable-cleanup failure.

A terminal authorization error has no credential publication. The SDK
acknowledges and finalizes it before throwing the exact typed OAuth error.

## Retry, crash, and reload behavior

- An ambiguous bootstrap stays `prepared`. The next live-phase attempt sends
  the same `create` body and capabilities. At local expiry it sends
  `terminal_only`; only authenticated terminal classification releases
  custody.
- An ambiguous PAR stays `par_pending`. The next attempt sends the same body,
  idempotency key, tab secret, cancellation secret, cookie, and CSRF lineage.
- Relay transport loss or `503 unavailable` keeps the same transaction,
  PKCE verifier, and DPoP key. A retry redelivers or completes the same
  one-use exchange.
- The SDK persists success or terminal-error classification before
  acknowledgement. It never persists the token envelope.
- An ambiguous acknowledgement is retried with the capability body. A server
  already in `publishing` or `adopted` returns `204`.
- A crash in `redeeming` or a relay retry state redelivers the exact envelope.
  Once `awaiting_ack` is durable, a reload has lost any parsed bearer material
  and does not relay again.
- Reload with a durable success settlement rejects the exact unavailable
  family, then reports delivery unavailable so the browser client can obtain
  one fresh silent grant.
- Reload with a durable terminal settlement rejects the exact transaction and
  re-surfaces its persisted OAuth error. It does not use success
  delivery-unavailable recovery.
- Finalization is exactly retryable. A crash that loses locally published
  credentials does not treat server finalization as proof that those
  credentials still exist; it compensates when the deadline permits.
- Rejection is persisted before transport. Network loss and `503` move to
  `reject_retry`. An exact rejected tombstone returns `204`.
- Exact `400` or `403` `{"error":"invalid_request"}` during rejection moves
  to `reject_blocked`. The SDK retains any owned live slot and its cancellation
  evidence instead of reporting fake success or starting a replacement
  transaction. Malformed responses and other ambiguous failures remain
  `reject_retry`.

Protocol operations use a fixed 15-second implementation deadline. The
effective deadline is the earlier of that value and transaction expiry. The
deadline includes streaming body consumption. Lifecycle invalidation aborts
owned fetches and retry waits immediately.

PAR, acknowledgement, finalization, and rejection use at most three immediate
attempts with 100 ms and 200 ms waits between attempts. A later caller or page
reload may resume only the exact durable transaction. No retry creates a new
grant, key, PAR, or cancellation capability.

Iframe authorization has a configured callback bound of at most 60 seconds.
Its timer uses the earlier persisted navigation or transaction deadline;
equality times out immediately.

IndexedDB upgrades recognize only the exact historical version-2
generation-scoped key, the later version-2 origin key, and the version-3
origin key. Slot reference and expiry must exactly match the referenced live
record. Migration never infers `published` from a missing legacy slot. When
multiple exact transaction-bound owners collapse onto one origin, the upgrade
retains one deterministic origin slot as a barrier and atomically converts
the other owners to whitelist-built, cancellation-only `reject_retry` records.
Transaction IDs, cancellation capabilities, generation bindings, and
deadlines remain exact; migration never extends them. A live `par_pending`
owner is retained because its server outcome is unknown. Multiple live
`par_pending` owners, `reject_blocked` custody, malformed live cancellation
authority, and any unknown member on a live legacy record, including a
structured-cloneable alias of known key material, abort the atomic upgrade
without partial writes. Persisted cancellation-only records have one exact
member set, plus either both execution-lease members or neither. Legacy
`navigating` custody without a reusable navigation lease is converted to
exact cancellation custody rather than silently discarded.

## Privacy invariants

Authorization code, OAuth state, OIDC nonce, PKCE material, request URI,
transaction ID, tab secret, idempotency key, cancellation secret, DPoP private
material, and tokens MUST NOT appear in a navigation URL, fragment, form post,
or `postMessage`.

Bearer material is memory-only in the browser. Cookies are `HttpOnly`.
Persistent browser storage contains only bounded protocol custody and
non-extractable key handles. Protocol requests and responses are non-cacheable
and use no-referrer behavior.

Malformed envelopes, invalid bindings, conflicting transactions, unsupported
states, unavailable durable settlement, and failed proof validation are
fatal. The SDK does not invent a response, silently release blocked custody,
or downgrade response-vault DPoP to Bearer.
