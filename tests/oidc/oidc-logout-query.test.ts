import { describe, expect, it } from 'vitest'
import { OidcClient } from 'oidc-client-ts'

describe('oidc-client-ts logout query parameters', () => {
  it('uses per-request parameters instead of the authorization audience', async () => {
    const issuer = 'https://id.atol.test'
    const client = new OidcClient({
      authority: issuer,
      client_id: 'atol-console',
      redirect_uri: 'https://console.atol.test/callback',
      extraQueryParams: { audience: 'atol-management-api' },
      metadata: {
        issuer,
        authorization_endpoint: `${issuer}/auth/authorize`,
        token_endpoint: `${issuer}/auth/token`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        end_session_endpoint: `${issuer}/auth/logout`,
      },
    })

    const request = await client.createSignoutRequest({
      post_logout_redirect_uri: 'https://console.atol.test/logout',
      extraQueryParams: {},
    })

    const query = new URL(request.url).searchParams
    expect(query.get('post_logout_redirect_uri')).toBe('https://console.atol.test/logout')
    expect(query.has('audience')).toBe(false)
  })
})
