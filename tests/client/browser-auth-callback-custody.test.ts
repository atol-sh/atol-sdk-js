/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  CLIENT_ID,
  ISSUER,
  LoginRequiredError,
  OAuthProtocolError,
  REDIRECT,
  makeAccessToken,
  makeClient,
  makeIDToken,
  makeJWT,
  manager,
  mockAccessVerify,
  mockAuthorize,
  mockExchange,
  mockVerify,
  tokenResponse,
} from './browser-auth-harness'
import {
  OrdinaryAuthorizationPendingError,
  OrdinaryBrowserAuthorization,
  type OrdinaryAuthorizationCallbackRecovery,
} from '../../src/oidc/ordinary-authorization'
import { NetworkError } from '../../src/oidc/token-recovery'
import type { CredentialGenerationSnapshot } from '../../src/oidc/credential-generation'

function pendingRecovery(
  generation: CredentialGenerationSnapshot,
  compensationRequired: boolean,
) {
  const complete = vi.fn(async () => undefined)
  const discard = vi.fn(async () => undefined)
  const release = vi.fn(async () => undefined)
  const markCodeIssued = vi.fn(async () => undefined)
  const recovery: OrdinaryAuthorizationCallbackRecovery = {
    callback: {
      code: 'durable-auth-code',
      codeVerifier: 'durable-verifier',
      redirectUri: REDIRECT,
      nonce: 'durable-nonce',
      credentialGeneration: generation,
    },
    custody: {
      dpopKey: null,
      compensationRequired,
      complete,
      discard,
      release,
      markCodeIssued,
    },
  }
  return {
    recovery,
    complete,
    discard,
    release,
    markCodeIssued,
  }
}

function installNoSessionRenewal(events: string[]): void {
  mockAuthorize.mockImplementation(async () => {
    events.push('silent-renew')
    throw new LoginRequiredError()
  })
}

describe('ordinary callback crash recovery', () => {
  it('revokes compensation custody before reading a User persisted by a crashed callback', async () => {
    window.history.replaceState({}, '', '/navigated-away')
    const events: string[] = []
    let storedUser: Record<string, unknown> | null = null
    manager.storeUser.mockImplementation(async (user) => {
      storedUser = user as Record<string, unknown>
    })
    await manager.storeUser({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'orphaned-refresh-token',
      token_type: 'bearer',
      expired: false,
    })
    manager.removeUser.mockImplementation(async () => {
      events.push('remove-user')
      storedUser = null
    })
    manager.getUser.mockImplementation(async () => {
      events.push('get-user')
      return storedUser
    })
    let custody:
      | ReturnType<typeof pendingRecovery>
      | undefined
    const claim = vi
      .spyOn(
        OrdinaryBrowserAuthorization.prototype,
        'claimPendingCallback',
      )
      .mockImplementationOnce(async (generation) => {
        events.push('claim-custody')
        custody = pendingRecovery(generation, true)
        return custody.recovery
      })
      .mockResolvedValue(null)
    mockExchange.mockImplementation(async (...args) => {
      events.push('exact-replay')
      expect(args.slice(0, 5)).toEqual([
        ISSUER,
        CLIENT_ID,
        'durable-auth-code',
        REDIRECT,
        'durable-verifier',
      ])
      throw new OAuthProtocolError('invalid_grant')
    })
    installNoSessionRenewal(events)

    const client = makeClient()
    await expect(client.init()).resolves.toMatchObject({
      isAuthenticated: false,
    })

    expect(events).toEqual([
      'claim-custody',
      'remove-user',
      'exact-replay',
      'get-user',
      'silent-renew',
    ])
    expect(custody?.discard).toHaveBeenCalledOnce()
    expect(custody?.complete).not.toHaveBeenCalled()
    expect(custody?.release).not.toHaveBeenCalled()
    expect(manager.storeUser).toHaveBeenCalledOnce()
    claim.mockRestore()
    client.destroy()
  })

  it('settles an ambiguous pre-response crash by exact issue then replay revocation', async () => {
    window.history.replaceState({}, '', '/navigated-away')
    const events: string[] = []
    manager.removeUser.mockImplementation(async () => {
      events.push('remove-user')
    })
    manager.getUser.mockImplementation(async () => {
      events.push('get-user')
      return null
    })
    let custody:
      | ReturnType<typeof pendingRecovery>
      | undefined
    const claim = vi
      .spyOn(
        OrdinaryBrowserAuthorization.prototype,
        'claimPendingCallback',
      )
      .mockImplementationOnce(async (generation) => {
        custody = pendingRecovery(generation, false)
        return custody.recovery
      })
      .mockResolvedValue(null)
    mockExchange
      .mockImplementationOnce(async (...args) => {
        events.push(`exchange:${String(args[2])}`)
        return tokenResponse()
      })
      .mockImplementationOnce(async (...args) => {
        events.push(`replay:${String(args[2])}`)
        throw new OAuthProtocolError('invalid_grant')
      })
    installNoSessionRenewal(events)

    const client = makeClient()
    await expect(client.init()).resolves.toMatchObject({
      isAuthenticated: false,
    })

    expect(events).toEqual([
      'remove-user',
      'exchange:durable-auth-code',
      'replay:durable-auth-code',
      'get-user',
      'silent-renew',
    ])
    expect(mockExchange.mock.calls[0].slice(0, 5)).toEqual(
      mockExchange.mock.calls[1].slice(0, 5),
    )
    expect(custody?.markCodeIssued).toHaveBeenCalledOnce()
    expect(custody?.discard).toHaveBeenCalledOnce()
    expect(custody?.complete).not.toHaveBeenCalled()
    claim.mockRestore()
    client.destroy()
  })

  it('does not read persisted tokens or renew while recovery is nonterminal', async () => {
    window.history.replaceState({}, '', '/navigated-away')
    const claim = vi
      .spyOn(
        OrdinaryBrowserAuthorization.prototype,
        'claimPendingCallback',
      )
      .mockImplementation(async (generation) =>
        pendingRecovery(generation, true).recovery,
      )
    mockExchange.mockRejectedValue(
      new OAuthProtocolError('server_error'),
    )

    const client = makeClient()
    await expect(client.init()).rejects.toBeInstanceOf(
      OrdinaryAuthorizationPendingError,
    )
    expect(manager.removeUser).toHaveBeenCalledOnce()
    expect(manager.getUser).not.toHaveBeenCalled()
    expect(mockAuthorize).not.toHaveBeenCalled()
    claim.mockRestore()
    client.destroy()
  })
})

describe('ordinary callback response URL custody', () => {
  it('restores the exact redirect URI after claim even when exchange is ambiguous', async () => {
    window.history.replaceState(
      {},
      '',
      '/cb?code=authcode&state=state-value&iss=provider&keep=untrusted#fragment',
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    mockExchange.mockRejectedValue(
      new NetworkError('response was lost'),
    )

    const client = makeClient()
    await expect(client.init()).rejects.toBeInstanceOf(
      OrdinaryAuthorizationPendingError,
    )
    const current = new URL(window.location.href)
    expect(current.pathname).toBe('/cb')
    expect(current.search).toBe('')
    expect(current.hash).toBe('')
    client.destroy()
  })

  it('preserves the exact registered redirect query after success', async () => {
    const redirect = `${REDIRECT}?tenant=alpha`
    window.history.replaceState(
      {},
      '',
      '/cb?tenant=alpha&code=authcode&state=state-value&iss=provider#fragment',
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })

    const client = makeClient(false, false, false, redirect)
    await expect(client.completeLogin()).resolves.toMatchObject({
      isAuthenticated: true,
    })

    expect(window.location.href).toBe(redirect)
    client.destroy()
  })

  it('replays the exact code, verifier, and DPoP key before deleting rejected tokens', async () => {
    window.history.replaceState(
      {},
      '',
      '/cb?code=authcode&state=state-value',
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    mockVerify.mockRejectedValue(new Error('nonce mismatch'))
    mockAccessVerify.mockImplementation(async (token) =>
      JSON.parse(
        Buffer.from(
          token.split('.')[1],
          'base64url',
        ).toString(),
      ),
    )
    mockExchange
      .mockImplementationOnce(async (...args) => {
        const signer = args[5] as unknown as {
          thumbprint(): Promise<string>
        }
        return tokenResponse({
          access_token: makeJWT({
            sub: 'user-1',
            exp: Math.floor(Date.now() / 1000) + 3600,
            cnf: { jkt: await signer.thumbprint() },
          }),
          token_type: 'DPoP',
        })
      })
      .mockRejectedValueOnce(
        new OAuthProtocolError('invalid_grant'),
      )

    const client = makeClient({ required: true })
    await expect(client.completeLogin()).rejects.toThrow(
      /callback failed/i,
    )

    expect(mockExchange).toHaveBeenCalledTimes(2)
    expect(mockExchange.mock.calls[0].slice(0, 5)).toEqual(
      mockExchange.mock.calls[1].slice(0, 5),
    )
    expect(mockExchange.mock.calls[0][5]).toBe(
      mockExchange.mock.calls[1][5],
    )
    expect(manager.storeUser).not.toHaveBeenCalled()
    expect(window.location.search).toBe('')
    client.destroy()
  })
})
