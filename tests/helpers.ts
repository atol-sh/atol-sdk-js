/** Shared test fixtures: unsigned JWTs with controllable claims. */

function b64url(json: object): string {
  return btoa(JSON.stringify(json))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/** Build a structurally-valid (unsigned) JWT with the given payload. */
export function makeJWT(payload: Record<string, unknown>): string {
  return `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url(payload)}.sig`
}

/** An access token expiring `inSeconds` from now. */
export function makeAccessToken(inSeconds = 3600): string {
  return makeJWT({
    sub: 'user-1',
    exp: Math.floor(Date.now() / 1000) + inSeconds,
  })
}

/** An ID token carrying the standard Atol claims. */
export function makeIDToken(overrides: Record<string, unknown> = {}): string {
  return makeJWT({
    sub: 'user-1',
    email: 'remi@example.test',
    email_verified: true,
    name: 'Remi',
    'atol:auth_method': 'oidc',
    'atol:mfa_verified': true,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  })
}
