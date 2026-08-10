/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  CLIENT_ID,
  ISSUER,
  LoginRequiredError,
  REDIRECT,
  makeAccessToken,
  makeClient,
  makeIDToken,
  manager,
  mockAuthorize,
} from './browser-auth-harness'
import { rotateLogoutGeneration } from '../../src/oidc/credential-generation'

describe('createAtolBrowserAuth -- MEMORY-ONLY tokens', () => {
  it('persists only non-secret generation state and no tokens', async () => {
    const at = makeAccessToken()
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: at,
      id_token: makeIDToken(),
      refresh_token: 'rt_secret_value',
    })
    const client = makeClient()
    await client.init()

    const localValues: string[] = []
    for (let i = 0; i < localStorage.length; i++) {
      localValues.push(localStorage.getItem(localStorage.key(i)!) ?? '')
    }
    expect(localValues).toHaveLength(1)
    expect(JSON.parse(localValues[0])).toMatchObject({
      version: 1,
      generation: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      status: 'active',
    })
    expect(localValues.join('|')).not.toContain(at)
    expect(localValues.join('|')).not.toContain('rt_secret_value')
    // Nothing token-shaped in sessionStorage (the real UserManager keeps
    // only PKCE state; here the mock stores nothing).
    const dump: string[] = []
    for (let i = 0; i < sessionStorage.length; i++) {
      dump.push(sessionStorage.getItem(sessionStorage.key(i)!) ?? '')
    }
    expect(dump.join('|')).not.toContain('rt_secret_value')
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- getAccessToken', () => {
  it('returns the current token on the fresh fast-path', async () => {
    const at = makeAccessToken(3600)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: at,
      id_token: makeIDToken(),
    })
    const client = makeClient()
    await client.init()

    const res = await client.getAccessToken()
    expect(res?.token).toBe(at)
    expect(res?.proof).toBeUndefined()
    client.destroy()
  })

  it('returns a DPoP-bound proof when dpop is active and opts.dpop is passed', async () => {
    const at = makeAccessToken(3600)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: at,
      id_token: makeIDToken(),
    })
    const client = makeClient(true)
    await client.init()
    expect(client.isDPoPActive()).toBe(true)

    const res = await client.getAccessToken({
      dpop: { method: 'GET', url: 'https://api.example.com/me' },
    })
    expect(res?.token).toBeTruthy()
    expect(res?.token).not.toBe(at)
    expect(
      JSON.parse(Buffer.from(res!.token.split('.')[1], 'base64url').toString())
        .cnf?.jkt,
    ).toBeTruthy()
    expect(res?.proof).toBeTruthy()
    // Proof is a dpop+jwt.
    const header = JSON.parse(
      Buffer.from(res!.proof!.split('.')[0], 'base64url').toString(),
    )
    expect(header.typ).toBe('dpop+jwt')
    client.destroy()
  })

  it('resolves undefined when there is no session', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient()
    await client.init()
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- getIdToken', () => {
  it('returns the current ID token after login and undefined after logout', async () => {
    const idToken = makeIDToken()
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idToken,
      refresh_token: 'rt',
    })
    manager.getUser.mockResolvedValue({ id_token: idToken })

    const client = makeClient(false, true)
    await client.init()
    // The raw ID token is readable so bindings can extract issuer-specific
    // claims (e.g. an encryption-key claim) without re-implementing storage.
    expect(client.getIdToken()).toBe(idToken)

    await client.logout()
    expect(client.getIdToken()).toBeUndefined()
    client.destroy()
  })

  it('returns undefined when there is no session', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient()
    await client.init()
    expect(client.getIdToken()).toBeUndefined()
    client.destroy()
  })

  it('fails closed when a missed cross-tab logout rotates authority', async () => {
    const idToken = makeIDToken()
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idToken,
    })

    const client = makeClient()
    await client.init()
    rotateLogoutGeneration({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })

    expect(() => client.getIdToken()).toThrow(
      'credential transaction was superseded',
    )
    expect(client.getIdToken()).toBeUndefined()
    await vi.waitFor(() => expect(manager.removeUser).toHaveBeenCalled())
    client.destroy()
  })
})
