/**
 * loadPermissions wire behavior + permissionKey.
 *
 * loadPermissions targets the control-plane API host (NOT the OIDC
 * authority), attaches Bearer or DPoP correctly, validates the response
 * shape, and denies by default.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { loadPermissions, permissionKey } from '../../src/permissions/permissions'

const API_URL = 'https://api.atol.test'
const KEY_ID = 'atol_kid_test'
const TOKEN = 'at_123'

const baseOpts = {
  apiUrl: API_URL,
  keyId: KEY_ID,
  accessToken: TOKEN,
  userId: 'user-1',
  orgId: 'org-1',
  checks: [
    { action: 'edit', resource: 'publication' },
    { action: 'manage', resource: 'team' },
  ],
}

function mockFetch(body: unknown, ok = true, status = 200) {
  const stub = vi.fn().mockResolvedValue({ ok, status, json: async () => body })
  vi.stubGlobal('fetch', stub)
  return stub
}

beforeEach(() => vi.restoreAllMocks())
afterEach(() => vi.unstubAllGlobals())

describe('permissionKey', () => {
  it('joins action and resource', () => {
    expect(permissionKey('edit', 'publication')).toBe('edit:publication')
  })
  it('handles a resource with an ID', () => {
    expect(permissionKey('manage', 'team:team-123')).toBe('manage:team:team-123')
  })
})

describe('loadPermissions', () => {
  it('POSTs to the API host BatchCheckAccess endpoint with Bearer auth', async () => {
    const stub = mockFetch({ results: [{ allowed: true }, { allowed: false }] })
    const perms = await loadPermissions(baseOpts)

    const [url, init] = stub.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`${API_URL}/atol.api.v1.AccessService/BatchCheckAccess`)
    const headers = init.headers as Record<string, string>
    expect(headers['Authorization']).toBe(`Bearer ${TOKEN}`)
    expect(headers['X-Atol-Key']).toBe(KEY_ID)
    expect(headers['DPoP']).toBeUndefined()

    // Body shape: user:<sub>, relation=action, object=resource.
    const body = JSON.parse(init.body as string)
    expect(body.orgId).toBe('org-1')
    expect(body.checks[0]).toEqual({
      user: 'user:user-1',
      relation: 'edit',
      object: 'publication',
    })

    expect(perms.get('edit:publication')).toBe(true)
    expect(perms.get('manage:team')).toBe(false)
  })

  it('uses the DPoP auth scheme with a bound proof when a signer is supplied', async () => {
    const stub = mockFetch({ results: [{ allowed: true }, { allowed: true }] })
    const signProof = vi.fn().mockResolvedValue('proof.jwt.sig')
    await loadPermissions({ ...baseOpts, dpop: { signProof } })

    const headers = (stub.mock.calls[0] as [string, RequestInit])[1].headers as Record<
      string,
      string
    >
    expect(headers['Authorization']).toBe(`DPoP ${TOKEN}`)
    expect(headers['DPoP']).toBe('proof.jwt.sig')
    // The proof must bind the access token via ath (RFC 9449 §4.3).
    expect(signProof).toHaveBeenCalledWith(
      'POST',
      `${API_URL}/atol.api.v1.AccessService/BatchCheckAccess`,
      { accessToken: TOKEN },
    )
  })

  it('strips a trailing slash on the API URL', async () => {
    const stub = mockFetch({ results: [{ allowed: true }, { allowed: true }] })
    await loadPermissions({ ...baseOpts, apiUrl: `${API_URL}/` })
    const [url] = stub.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`${API_URL}/atol.api.v1.AccessService/BatchCheckAccess`)
  })

  it('throws when the result count does not match the check count', async () => {
    mockFetch({ results: [{ allowed: true }] }) // 1 result, 2 checks
    await expect(loadPermissions(baseOpts)).rejects.toThrow(/results for/)
  })

  it('coerces non-true allowed values to deny', async () => {
    mockFetch({ results: [{ allowed: 'yes' }, {}] })
    const perms = await loadPermissions(baseOpts)
    expect(perms.get('edit:publication')).toBe(false)
    expect(perms.get('manage:team')).toBe(false)
  })

  it('throws on a non-ok response', async () => {
    mockFetch({}, false, 500)
    await expect(loadPermissions(baseOpts)).rejects.toThrow(/HTTP 500/)
  })

  it('treats a response with no results field as zero results (count mismatch -> throw)', async () => {
    mockFetch({}) // ok, but { results } is undefined -> [] -> 0 != 2 checks
    await expect(loadPermissions(baseOpts)).rejects.toThrow(/0 results for 2 checks/)
  })

  it('returns an empty map without calling fetch when there are no checks', async () => {
    const stub = mockFetch({ results: [] })
    const perms = await loadPermissions({ ...baseOpts, checks: [] })
    expect(perms.size).toBe(0)
    expect(stub).not.toHaveBeenCalled()
  })
})
