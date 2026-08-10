/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  ORG_A,
  ORG_B,
  ORG_C,
  OAuthProtocolError,
  makeAccessToken,
  makeClient,
  makeIDToken,
  makeOrgAccessToken,
  manager,
  mockAuthorize,
  ordinaryBeginSpy,
  mockExchange,
  organizationClaim,
  tokenResponse,
  type BrowserAuthSession,
} from './browser-auth-harness'

describe('createAtolBrowserAuth -- organization credential context', () => {
  async function loggedInForOrganization(organizationId: string) {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(organizationId),
      id_token: makeIDToken({ 'atol:org_id': organizationId }),
    })
    const client = makeClient()
    await client.init()
    window.history.replaceState({}, '', '/')
    return client
  }

  it('[R10] rejects non-canonical organization claims from real token responses', async () => {
    const nonCanonical = ORG_A.toLowerCase()
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(nonCanonical),
      id_token: makeIDToken({ 'atol:org_id': nonCanonical }),
    })

    const client = makeClient()
    await expect(client.completeLogin()).rejects.toThrow(/OIDC callback failed/)
    let session!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      session = value as BrowserAuthSession
    })
    unsubscribe()

    expect(session.isAuthenticated).toBe(false)
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('[R36] rejects a ULID whose high prefix cannot encode 128 bits', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockClear()

    await expect(
      client.selectOrganization(`8${ORG_B.slice(1)}`),
    ).rejects.toThrow(/canonical ULID/)
    expect(mockAuthorize).not.toHaveBeenCalled()
    client.destroy()
  })

  it('[R10] does not let a generic renewal silently scope an unscoped session', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    const client = makeClient()
    await client.init()
    window.history.replaceState({}, '', '/')

    mockAuthorize.mockResolvedValue({ code: 'generic', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange
      .mockResolvedValueOnce(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_A),
        id_token: makeIDToken({ 'atol:org_id': ORG_A }),
      }),
      )
      .mockRejectedValueOnce(
        new OAuthProtocolError('invalid_grant'),
      )

    await expect(client.forceRenew()).rejects.toThrow(/requested organization/)
    expect(organizationClaim((await client.getAccessToken())?.token)).toBeUndefined()
    expect(organizationClaim(client.getIdToken())).toBeUndefined()
    client.destroy()
  })

  it('[R10] starts a distinct organization grant and ignores an older generic renewal result', async () => {
    const client = await loggedInForOrganization(ORG_A)
    let resolveGenericAuthorize:
      | ((result: { code: string; state: string; codeVerifier: string; nonce: string }) => void)
      | undefined
    mockAuthorize
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveGenericAuthorize = resolve
          }),
      )
      .mockResolvedValueOnce({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange.mockImplementation(async (_authority, _clientId, code) =>
      tokenResponse(
        code === 'organization-b'
          ? {
              access_token: makeOrgAccessToken(ORG_B),
              id_token: makeIDToken({ 'atol:org_id': ORG_B }),
            }
          : {
              access_token: makeOrgAccessToken(ORG_A),
              id_token: makeIDToken({ 'atol:org_id': ORG_A }),
            },
      ),
    )

    const genericRenewal = client.forceRenew()
    await vi.waitFor(() => expect(mockAuthorize).toHaveBeenCalledTimes(1))
    const selection = client.selectOrganization(ORG_B)
    await new Promise((resolve) => setTimeout(resolve, 0))
    const authorizeCallsBeforeGenericCompletes = mockAuthorize.mock.calls.length

    resolveGenericAuthorize!({ code: 'generic-a', state: 's-a', codeVerifier: 'v-a', nonce: 'nonce-v-a' })
    const [, selectionResult] = await Promise.allSettled([genericRenewal, selection])
    let finalSession!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      finalSession = value as BrowserAuthSession
    })
    unsubscribe()
    const finalAccessToken = (await client.getAccessToken())?.token
    const finalIdToken = client.getIdToken()
    client.destroy()

    expect(authorizeCallsBeforeGenericCompletes).toBe(2)
    expect(selectionResult.status).toBe('fulfilled')
    expect(
      selectionResult.status === 'fulfilled' ? selectionResult.value.organizationId : undefined,
    ).toBe(ORG_B)
    expect(finalSession.organizationId).toBe(ORG_B)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_B)
    expect(organizationClaim(finalIdToken)).toBe(ORG_B)
  })

  it('[R10] commits only the latest of two organization selections completed out of order', async () => {
    const client = await loggedInForOrganization(ORG_A)
    let resolveFirstAuthorize:
      | ((result: { code: string; state: string; codeVerifier: string; nonce: string }) => void)
      | undefined
    mockAuthorize
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveFirstAuthorize = resolve
          }),
      )
      .mockResolvedValueOnce({ code: 'organization-c', state: 's-c', codeVerifier: 'v-c', nonce: 'nonce-v-c' })
    mockExchange.mockImplementation(async (_authority, _clientId, code) => {
      const organizationId = code === 'organization-c' ? ORG_C : ORG_B
      return tokenResponse({
        access_token: makeOrgAccessToken(organizationId),
        id_token: makeIDToken({ 'atol:org_id': organizationId }),
      })
    })

    const firstSelection = client.selectOrganization(ORG_B)
    await vi.waitFor(() => expect(mockAuthorize).toHaveBeenCalledTimes(1))
    const latestSelection = client.selectOrganization(ORG_C)
    const latestSession = await latestSelection
    resolveFirstAuthorize!({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    const firstResult = await Promise.allSettled([firstSelection])

    let finalSession!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      finalSession = value as BrowserAuthSession
    })
    unsubscribe()
    const finalAccessToken = (await client.getAccessToken())?.token
    const finalIdToken = client.getIdToken()
    client.destroy()

    expect(firstResult[0]?.status).toBe('rejected')
    expect(latestSession.organizationId).toBe(ORG_C)
    expect(finalSession.organizationId).toBe(ORG_C)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_C)
    expect(organizationClaim(finalIdToken)).toBe(ORG_C)
  })

  it('[R10] rejects mismatched access and ID token organizations without a partial update', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockResolvedValue({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange
      .mockResolvedValueOnce(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_B),
        id_token: makeIDToken({ 'atol:org_id': ORG_A }),
      }),
      )
      .mockRejectedValueOnce(
        new OAuthProtocolError('invalid_grant'),
      )

    let selectionError: unknown
    try {
      await client.selectOrganization(ORG_B)
    } catch (error) {
      selectionError = error
    }
    const finalAccessToken = (await client.getAccessToken())?.token
    const finalIdToken = client.getIdToken()
    client.destroy()

    expect(selectionError).toBeInstanceOf(Error)
    expect((selectionError as Error | undefined)?.message).toMatch(/organization.*mismatch/i)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_A)
    expect(organizationClaim(finalIdToken)).toBe(ORG_A)
  })

  it('[R10] exposes the selected organization once as credential context, not user identity', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockResolvedValue({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange.mockResolvedValue(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_B),
        id_token: makeIDToken({ 'atol:org_id': ORG_B }),
      }),
    )

    const selected = await client.selectOrganization(ORG_B)
    const authorizeStart = ordinaryBeginSpy().mock.calls.at(-1)?.[0] as
      | {
          intent: {
            extraQueryParams?: Record<string, string>
          }
        }
      | undefined
    const accessToken = (await client.getAccessToken())?.token
    const idToken = client.getIdToken()
    const user = selected.user as unknown as Record<string, unknown>
    client.destroy()

    expect(
      authorizeStart?.intent.extraQueryParams?.atol_org_id,
    ).toBe(ORG_B)
    expect(selected.organizationId).toBe(ORG_B)
    expect(organizationClaim(accessToken)).toBe(ORG_B)
    expect(organizationClaim(idToken)).toBe(ORG_B)
    expect(user.orgId).toBeUndefined()
    expect(user.roles).toBeUndefined()
    expect(user.plan).toBeUndefined()
  })

  it('[R31] rejects an organization grant that changes the authenticated subject', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockResolvedValue({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange
      .mockResolvedValueOnce(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_B, 3600, { sub: 'user-2' }),
        id_token: makeIDToken({ sub: 'user-2', 'atol:org_id': ORG_B }),
      }),
      )
      .mockRejectedValueOnce(
        new OAuthProtocolError('invalid_grant'),
      )

    await expect(client.selectOrganization(ORG_B)).rejects.toThrow(/subject/i)
    let finalSession!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      finalSession = value as BrowserAuthSession
    })
    unsubscribe()
    const finalAccessToken = (await client.getAccessToken())?.token
    client.destroy()

    expect(finalSession.user?.id).toBe('user-1')
    expect(finalSession.organizationId).toBe(ORG_A)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_A)
  })
})
