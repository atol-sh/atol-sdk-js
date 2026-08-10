/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it } from 'vitest'
import {
  OPAQUE_A,
  OPAQUE_C,
  REDIRECT,
  bootstrap,
  expectNoActiveReference,
  installFetch,
  installResponseVaultProtocolHooks,
  issuerBootstrap,
  newVault,
  noContent,
  pushed,
} from './response-vault-protocol-test-support'

installResponseVaultProtocolHooks()

describe('public response-vault validation', () => {
  it.each([
    ['localhost', 'http://localhost:8080', 'http://localhost:3000/callback'],
    [
      'localhost subdomain',
      'http://id.localhost:8080',
      'http://app.localhost:3000/callback',
    ],
    [
      'IPv4 loopback',
      'http://127.1.2.3:8080',
      'http://127.0.0.1:3000/callback',
    ],
    ['IPv6 loopback', 'http://[::1]:8080', 'http://[::1]:3000/callback'],
  ])(
    'accepts trustworthy %s development origins',
    (_name, issuer, redirectUri) => {
      expect(() => newVault({ issuer, redirectUri })).not.toThrow()
    },
  )

  it('accepts registered client-specific bindings and OIDC values', async () => {
    installFetch(
      [
        bootstrap(OPAQUE_A),
        pushed(),
        issuerBootstrap(OPAQUE_C),
        noContent(),
        noContent(),
      ],
      {
        clientId: 'customer-dashboard',
        redirectUri: 'https://app.example.com/oidc/complete',
        audience: 'urn:example:resource-api',
      },
    )
    const vault = newVault({
      clientId: 'customer-dashboard',
      redirectUri: 'https://app.example.com/oidc/complete',
      audience: 'urn:example:resource-api',
      scope: 'openid address custom:read custom:write',
    })
    await expect(
      vault.beginInteractive({
        acrValues: 'urn:example:loa:2 password',
      }),
    ).resolves.toBeUndefined()
    await vault.invalidateLifecycle()
  })

  it.each([
    ['invalid issuer URL', { issuer: 'not a URL' }],
    ['non-network issuer', { issuer: 'ftp://id.example.com' }],
    ['issuer credentials', { issuer: 'https://user@id.example.com' }],
    ['issuer path', { issuer: 'https://id.example.com/path' }],
    ['invalid redirect URL', { redirectUri: 'not a URL' }],
    [
      'redirect credentials',
      { redirectUri: 'https://user@app.example.com/callback' },
    ],
    ['redirect query', { redirectUri: `${REDIRECT}?code=leak` }],
    [
      'mixed redirect scheme',
      { issuer: 'http://localhost:8080', redirectUri: REDIRECT },
    ],
    ['empty client', { clientId: '' }],
    ['oversized client', { clientId: 'c'.repeat(513) }],
    ['empty audience', { audience: '' }],
    ['oversized audience', { audience: 'a'.repeat(513) }],
    ['empty scope', { scope: '' }],
    ['oversized scope', { scope: 's'.repeat(513) }],
    ['duplicate scope', { scope: 'openid profile profile' }],
    ['missing openid', { scope: 'profile email' }],
    ['non-canonical scope whitespace', { scope: 'openid  profile' }],
    ['invalid scope character', { scope: 'openid profile\\email' }],
    ['zero iframe timeout', { iframeTimeoutMs: 0 }],
    ['fractional iframe timeout', { iframeTimeoutMs: 1.5 }],
    ['oversized iframe timeout', { iframeTimeoutMs: 300_001 }],
  ])('rejects %s', (_name, overrides) => {
    expect(() => newVault(overrides)).toThrow()
  })

  it.each([
    ['unsupported prompt', { prompt: 'consent' }],
    ['negative max_age', { maxAge: -1 }],
    ['fractional max_age', { maxAge: 1.5 }],
    ['oversized max_age', { maxAge: 86_401 }],
    ['empty ACR', { acrValues: '' }],
    ['non-canonical ACR whitespace', { acrValues: 'mfa  password' }],
    ['invalid ACR character', { acrValues: 'mfa\\password' }],
    ['non-canonical organization', { organizationId: 'organization-1' }],
  ])('rejects %s before creating browser authority', async (_name, intent) => {
    await expect(newVault().beginInteractive(intent)).rejects.toThrow(
      /authorization intent is invalid/,
    )
    expectNoActiveReference()
  })
})
