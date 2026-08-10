/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { beforeEach, describe, expect, it } from 'vitest'

import { createAtolBrowserAuth } from '../../src/client/browser-auth'

const ISSUER = 'https://id.example.com'
const CLIENT_ORIGIN = 'https://app.example.com'
const REDIRECT = `${CLIENT_ORIGIN}/callback`
const POST_LOGOUT_REDIRECT = `${CLIENT_ORIGIN}/logout`

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
})

function expectNoActiveReference(): void {
  expect(
    sessionStorage.getItem('atol:response-vault:v1:active'),
  ).toBeNull()
}

describe('createAtolBrowserAuth response-vault configuration', () => {
  it('rejects incompatible response-vault options before creating browser authority', () => {
    expect(() =>
      createAtolBrowserAuth({
        issuer: ISSUER,
        clientId: 'example-spa',
        redirectUri: REDIRECT,
        postLogoutRedirectUri: POST_LOGOUT_REDIRECT,
        audience: 'https://api.example.com',
        responseVault: true,
        dpop: false,
      }),
    ).toThrow(/requires DPoP/)
    expect(() =>
      createAtolBrowserAuth({
        issuer: ISSUER,
        clientId: 'example-spa',
        redirectUri: REDIRECT,
        postLogoutRedirectUri: POST_LOGOUT_REDIRECT,
        audience: 'https://api.example.com',
        responseVault: true,
        deriveEncryptionKey: true,
      }),
    ).toThrow(/does not support deriveEncryptionKey/)
    expect(() =>
      createAtolBrowserAuth({
        issuer: ISSUER,
        clientId: 'example-spa',
        redirectUri: REDIRECT,
        audience: 'https://api.example.com',
        responseVault: true,
      }),
    ).toThrow(/requires postLogoutRedirectUri/)
    expect(() =>
      createAtolBrowserAuth({
        issuer: ISSUER,
        clientId: 'example-spa',
        redirectUri: REDIRECT,
        postLogoutRedirectUri: 'https://evil.test/logout',
        audience: 'https://api.example.com',
        responseVault: true,
      }),
    ).toThrow(/redirectUri origin/)
    expect(() =>
      createAtolBrowserAuth({
        issuer: ISSUER,
        clientId: 'example-spa',
        redirectUri: REDIRECT,
        postLogoutRedirectUri: REDIRECT,
        audience: 'https://api.example.com',
        responseVault: true,
      }),
    ).toThrow(/must differ/)
    expectNoActiveReference()
  })
})
