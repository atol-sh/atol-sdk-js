/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  credentialGenerationSnapshot,
  logoutGenerationStorageKey,
  rotateLogoutGeneration,
} from '../../src/oidc/credential-generation'
import {
  CLIENT_ID,
  ISSUER,
  ORG_A,
  ORG_B,
  REDIRECT,
  makeAccessToken,
  makeClient,
  makeIDToken,
  makeOrgAccessToken,
  manager,
  mockAuthorize,
  mockExchange,
  mockRefresh,
  tokenResponse,
  type BrowserAuthSession,
} from './browser-auth-harness'

const binding = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  redirectUri: REDIRECT,
}

async function loggedIn(
  useRefreshTokens = false,
  organizationId?: string,
) {
  window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
  manager.signinRedirectCallback.mockResolvedValue({
    access_token: organizationId
      ? makeOrgAccessToken(organizationId, 90)
      : makeAccessToken(90),
    id_token: makeIDToken(
      organizationId ? { 'atol:org_id': organizationId } : {},
    ),
    refresh_token: 'rt_live',
  })
  const client = makeClient(false, useRefreshTokens)
  await client.init()
  window.history.replaceState({}, '', '/')
  return client
}

function dispatchGenerationChange(
  oldValue: string,
  newValue: string,
): void {
  window.dispatchEvent(
    new StorageEvent('storage', {
      key: logoutGenerationStorageKey(binding),
      oldValue,
      newValue,
      url: window.location.href,
    }),
  )
}

describe('createAtolBrowserAuth -- live credential-generation authority', () => {
  it('makes no refresh or authorize call when forceRenew starts stale', async () => {
    const client = await loggedIn(true)
    mockAuthorize.mockClear()
    mockRefresh.mockClear()
    rotateLogoutGeneration(binding)

    await expect(client.forceRenew()).resolves.toBeUndefined()

    expect(mockRefresh).not.toHaveBeenCalled()
    expect(mockAuthorize).not.toHaveBeenCalled()
    expect(await client.getAccessToken()).toBeUndefined()
    expect(client.getIdToken()).toBeUndefined()
    client.destroy()
  })

  it('revalidates live authority after an in-flight refresh grant', async () => {
    const client = await loggedIn(true)
    manager.storeUser.mockClear()
    let resolveRefresh:
      | ((value: ReturnType<typeof tokenResponse>) => void)
      | undefined
    mockRefresh.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveRefresh = resolve
        }),
    )

    const renewal = client.forceRenew()
    await vi.waitFor(() => expect(mockRefresh).toHaveBeenCalledTimes(1))
    rotateLogoutGeneration(binding)
    resolveRefresh!(
      tokenResponse({
        access_token: makeAccessToken(3600),
        refresh_token: 'rt_replacement',
      }),
    )

    await expect(renewal).resolves.toBeUndefined()
    expect(manager.storeUser).not.toHaveBeenCalled()
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('makes no token call when a proactive timer observes stale authority', async () => {
    vi.useFakeTimers()
    try {
      const client = await loggedIn(true)
      mockRefresh.mockClear()
      rotateLogoutGeneration(binding)

      await vi.advanceTimersByTimeAsync(31_000)

      expect(mockRefresh).not.toHaveBeenCalled()
      expect(await client.getAccessToken()).toBeUndefined()
      client.destroy()
    } finally {
      vi.useRealTimers()
    }
  })

  it('makes no authorize call when organization selection starts stale', async () => {
    const client = await loggedIn(false, ORG_A)
    mockAuthorize.mockClear()
    rotateLogoutGeneration(binding)

    await expect(client.selectOrganization(ORG_B)).rejects.toThrow(
      /superseded/,
    )

    expect(mockAuthorize).not.toHaveBeenCalled()
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('does not exchange a code when authority changes during organization authorize', async () => {
    const client = await loggedIn(false, ORG_A)
    mockAuthorize.mockClear()
    mockExchange.mockClear()
    let resolveAuthorize:
      | ((value: {
          code: string
          state: string
          codeVerifier: string
          nonce: string
        }) => void)
      | undefined
    mockAuthorize.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveAuthorize = resolve
        }),
    )

    const selection = client.selectOrganization(ORG_B)
    await vi.waitFor(() => expect(mockAuthorize).toHaveBeenCalledTimes(1))
    rotateLogoutGeneration(binding)
    resolveAuthorize!({
      code: 'stale-organization',
      state: 'state',
      codeVerifier: 'verifier',
      nonce: 'nonce',
    })

    await expect(selection).rejects.toThrow(/superseded/)
    expect(mockExchange).not.toHaveBeenCalled()
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('reconciles the current storage generation without BroadcastChannel or re-rotation', async () => {
    const originalBroadcastChannel = globalThis.BroadcastChannel
    Object.defineProperty(globalThis, 'BroadcastChannel', {
      configurable: true,
      value: undefined,
    })
    try {
      const client = await loggedIn()
      let latest!: BrowserAuthSession
      client.onSessionChange((session) => {
        latest = session as BrowserAuthSession
      })
      const previous = credentialGenerationSnapshot(binding)
      const key = logoutGenerationStorageKey(binding)
      const previousRecord = localStorage.getItem(key)!
      rotateLogoutGeneration(binding)
      const afterRotation = credentialGenerationSnapshot(binding)
      const nextRecord = localStorage.getItem(key)!

      dispatchGenerationChange(previousRecord, nextRecord)

      expect(latest.isAuthenticated).toBe(false)
      expect(await client.getAccessToken()).toBeUndefined()
      expect(client.getIdToken()).toBeUndefined()
      expect(credentialGenerationSnapshot(binding)).toEqual(afterRotation)
      expect(afterRotation.tabOwner).toBe(previous.tabOwner)
      client.destroy()
    } finally {
      Object.defineProperty(globalThis, 'BroadcastChannel', {
        configurable: true,
        value: originalBroadcastChannel,
      })
    }
  })

  it('ignores a delayed storage event after a newer generation establishes a session', async () => {
    const client = await loggedIn()
    const oldRecord = localStorage.getItem(
      logoutGenerationStorageKey(binding),
    )!
    rotateLogoutGeneration(binding)

    await client.beginLogin()
    window.history.replaceState({}, '', '/cb?code=fresh&state=fresh')
    const freshAccessToken = makeAccessToken(3600)
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: freshAccessToken,
      id_token: makeIDToken(),
    })
    await client.completeLogin()
    window.history.replaceState({}, '', '/')
    const currentGeneration = credentialGenerationSnapshot(binding)

    dispatchGenerationChange(
      localStorage.getItem(logoutGenerationStorageKey(binding))!,
      oldRecord,
    )

    expect((await client.getAccessToken())?.token).toBe(freshAccessToken)
    expect(client.getIdToken()).toBeDefined()
    expect(credentialGenerationSnapshot(binding)).toEqual(currentGeneration)
    client.destroy()
  })
})
