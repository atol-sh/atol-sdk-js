/**
 * Token-endpoint behavior: exchangeCode, refreshTokenGrant, and
 * revokeToken. Covers request shaping, OAuth error mapping (classified via
 * token-recovery), DPoP nonce challenge retry, and revocation.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import {
  exchangeCode,
  refreshTokenGrant,
  revokeToken,
  LoginRequiredError,
} from "../../src/oidc/silent-renew"
import {
  NetworkError,
  OAuthProtocolError,
  RecoveryAction,
  classifyRenewalError,
} from "../../src/oidc/token-recovery"

const AUTHORITY = "http://atol.localhost:9080"
const CLIENT_ID = "atol_kid_test"
const REFRESH = "rt_abc123"

function mockFetchOnce(response: { ok: boolean; status?: number; body: unknown }) {
  const stub = vi.fn().mockResolvedValueOnce({
    ok: response.ok,
    status: response.status ?? (response.ok ? 200 : 400),
    headers: new Headers(),
    json: async () => response.body,
    text: async () =>
      typeof response.body === "string" ? response.body : JSON.stringify(response.body),
  })
  vi.stubGlobal("fetch", stub)
  return stub
}

beforeEach(() => vi.restoreAllMocks())
afterEach(() => vi.unstubAllGlobals())

describe("exchangeCode", () => {
  it("POSTs an authorization_code grant with the PKCE verifier", async () => {
    const stub = mockFetchOnce({
      ok: true,
      body: { access_token: "at", token_type: "bearer", expires_in: 3600 },
    })
    await exchangeCode(AUTHORITY, CLIENT_ID, "the-code", "https://app/cb", "verifier-xyz")
    const [url, init] = stub.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`${AUTHORITY}/auth/token`)
    const body = new URLSearchParams(init.body as string)
    expect(body.get("grant_type")).toBe("authorization_code")
    expect(body.get("code")).toBe("the-code")
    expect(body.get("code_verifier")).toBe("verifier-xyz")
    expect(body.get("redirect_uri")).toBe("https://app/cb")
  })

  it("maps a non-ok exchange to a typed OAuth error", async () => {
    mockFetchOnce({ ok: false, status: 400, body: { error: "invalid_grant" } })
    const err = await exchangeCode(
      AUTHORITY,
      CLIENT_ID,
      "c",
      "https://app/cb",
      "v",
    ).catch((e) => e)
    expect(err).toBeInstanceOf(OAuthProtocolError)
    expect((err as OAuthProtocolError).code).toBe("invalid_grant")
  })

  it('retries the code exchange with the server nonce on a use_dpop_nonce challenge', async () => {
    const signProof = vi
      .fn()
      .mockResolvedValueOnce("proof-1")
      .mockResolvedValueOnce("proof-2")
    const stub = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        headers: new Headers({ "DPoP-Nonce": "n-exch" }),
        json: async () => ({ error: "use_dpop_nonce" }),
        text: async () => JSON.stringify({ error: "use_dpop_nonce" }),
        clone() {
          return this
        },
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ access_token: "at", token_type: "bearer", expires_in: 60 }),
      })
    vi.stubGlobal("fetch", stub)

    const tokens = await exchangeCode(
      AUTHORITY,
      CLIENT_ID,
      "code",
      "https://app/cb",
      "verifier",
      { signProof },
    )
    expect(tokens.access_token).toBe("at")
    expect(signProof).toHaveBeenNthCalledWith(2, "POST", `${AUTHORITY}/auth/token`, {
      nonce: "n-exch",
    })
  })

  it('does NOT retry when a 400 carries a non-JSON body (not a nonce challenge)', async () => {
    const signProof = vi.fn().mockResolvedValue("proof")
    const stub = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 400,
      headers: new Headers({ "DPoP-Nonce": "n" }),
      json: async () => {
        throw new Error("not json")
      },
      text: async () => "<html>Bad Request</html>",
      clone() {
        return this
      },
    })
    vi.stubGlobal("fetch", stub)
    // Non-JSON body -> isUseDpopNonce false -> no retry; the error surfaces.
    await expect(
      exchangeCode(AUTHORITY, CLIENT_ID, "c", "https://app/cb", "v", { signProof }),
    ).rejects.toBeDefined()
    expect(stub).toHaveBeenCalledTimes(1)
  })

  it('[R30] reuses the latest successful server nonce on the next token request', async () => {
    const signer = { signProof: vi.fn().mockResolvedValue('proof') }
    const stub = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'DPoP-Nonce': 'nonce-for-next-request' }),
        json: async () => ({ access_token: 'at-1', token_type: 'DPoP', expires_in: 60 }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ access_token: 'at-2', token_type: 'DPoP', expires_in: 60 }),
      })
    vi.stubGlobal('fetch', stub)

    await exchangeCode(AUTHORITY, CLIENT_ID, 'code-1', 'https://app/cb', 'verifier-1', signer)
    await exchangeCode(AUTHORITY, CLIENT_ID, 'code-2', 'https://app/cb', 'verifier-2', signer)

    expect(signer.signProof).toHaveBeenNthCalledWith(
      2,
      'POST',
      `${AUTHORITY}/auth/token`,
      { nonce: 'nonce-for-next-request' },
    )
  })
})

describe("refreshTokenGrant", () => {
  it("POSTs grant_type=refresh_token and returns the rotated tokens", async () => {
    const stub = mockFetchOnce({
      ok: true,
      body: {
        access_token: "at_new",
        id_token: "id_new",
        refresh_token: "rt_rotated",
        token_type: "bearer",
        expires_in: 3600,
      },
    })
    const tokens = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH)
    expect(tokens.access_token).toBe("at_new")
    expect(tokens.refresh_token).toBe("rt_rotated")

    const [url, init] = stub.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`${AUTHORITY}/auth/token`)
    expect(init.method).toBe("POST")
    const body = new URLSearchParams(init.body as string)
    expect(body.get("grant_type")).toBe("refresh_token")
    expect(body.get("client_id")).toBe(CLIENT_ID)
    expect(body.get("refresh_token")).toBe(REFRESH)
  })

  it("includes scope and audience when supplied", async () => {
    const stub = mockFetchOnce({
      ok: true,
      body: { access_token: "a", token_type: "bearer", expires_in: 60 },
    })
    await refreshTokenGrant(
      AUTHORITY,
      CLIENT_ID,
      REFRESH,
      "openid profile offline_access",
      "https://api.example.com",
    )
    const body = new URLSearchParams(
      (stub.mock.calls[0] as [string, RequestInit])[1].body as string,
    )
    expect(body.get("scope")).toBe("openid profile offline_access")
    expect(body.get("audience")).toBe("https://api.example.com")
  })

  it("maps invalid_grant to a ForceReauth-classified error", async () => {
    mockFetchOnce({
      ok: false,
      status: 400,
      body: { error: "invalid_grant", error_description: "refresh token expired" },
    })
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect(err).toBeInstanceOf(OAuthProtocolError)
    expect((err as OAuthProtocolError).code).toBe("invalid_grant")
    expect(classifyRenewalError(err)).toBe(RecoveryAction.ForceReauth)
  })

  it("maps invalid_request (lost HMAC secret) to ForceReauth", async () => {
    mockFetchOnce({
      ok: false,
      status: 400,
      body: { error: "invalid_request", error_description: "malformed token" },
    })
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect((err as OAuthProtocolError).code).toBe("invalid_request")
    expect(classifyRenewalError(err)).toBe(RecoveryAction.ForceReauth)
  })

  it("maps login_required to LoginRequiredError", async () => {
    mockFetchOnce({
      ok: false,
      status: 401,
      body: { error: "login_required", error_description: "session expired" },
    })
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect(err).toBeInstanceOf(LoginRequiredError)
    expect(err).toBeInstanceOf(OAuthProtocolError)
    expect(classifyRenewalError(err)).toBe(RecoveryAction.ForceReauth)
  })

  it("maps server_error (5xx) to a Retry-classified error", async () => {
    mockFetchOnce({
      ok: false,
      status: 500,
      body: { error: "server_error", error_description: "db down" },
    })
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect((err as OAuthProtocolError).code).toBe("server_error")
    expect(err).not.toBeInstanceOf(LoginRequiredError)
    expect(classifyRenewalError(err)).toBe(RecoveryAction.Retry)
  })

  it("maps a 5xx with a non-JSON body to server_error (Retry)", async () => {
    mockFetchOnce({ ok: false, status: 502, body: "<html>502 Bad Gateway</html>" })
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect((err as OAuthProtocolError).code).toBe("server_error")
    expect(classifyRenewalError(err)).toBe(RecoveryAction.Retry)
  })

  it("wraps fetch rejections in NetworkError (Retry)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce(new TypeError("Failed to fetch")))
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect(err).toBeInstanceOf(NetworkError)
    expect(classifyRenewalError(err)).toBe(RecoveryAction.Retry)
  })

  it("maps 429 (rate limited) to a transient error (Retry), not a sign-out", async () => {
    mockFetchOnce({ ok: false, status: 429, body: { error: "slow_down" } })
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect((err as OAuthProtocolError).code).toBe("temporarily_unavailable")
    expect(classifyRenewalError(err)).toBe(RecoveryAction.Retry)
  })

  it("retries once with the server nonce on a use_dpop_nonce challenge", async () => {
    const signProof = vi
      .fn()
      .mockResolvedValueOnce("proof-no-nonce")
      .mockResolvedValueOnce("proof-with-nonce")
    const stub = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ "DPoP-Nonce": "n-123" }),
        json: async () => ({ error: "use_dpop_nonce" }),
        text: async () => JSON.stringify({ error: "use_dpop_nonce" }),
        clone() {
          return this
        },
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ access_token: "at", token_type: "bearer", expires_in: 60 }),
      })
    vi.stubGlobal("fetch", stub)

    const tokens = await refreshTokenGrant(
      AUTHORITY,
      CLIENT_ID,
      REFRESH,
      undefined,
      undefined,
      { signProof },
    )
    expect(tokens.access_token).toBe("at")
    expect(stub).toHaveBeenCalledTimes(2)
    expect(signProof).toHaveBeenNthCalledWith(2, "POST", `${AUTHORITY}/auth/token`, {
      nonce: "n-123",
    })
  })

  it("attaches a DPoP proof header on the first attempt when a signer is supplied", async () => {
    const signProof = vi.fn().mockResolvedValue("the-proof")
    const stub = mockFetchOnce({
      ok: true,
      body: { access_token: "at", token_type: "bearer", expires_in: 60 },
    })
    await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH, undefined, undefined, {
      signProof,
    })
    const headers = (stub.mock.calls[0] as [string, RequestInit])[1].headers as Record<
      string,
      string
    >
    expect(headers["DPoP"]).toBe("the-proof")
  })
})

describe("revokeToken", () => {
  it("POSTs an RFC 7009 revocation for the refresh token by default", async () => {
    const stub = vi.fn().mockResolvedValue({ ok: true, status: 200 })
    vi.stubGlobal("fetch", stub)
    await revokeToken(AUTHORITY, CLIENT_ID, "rt_to_kill")
    const [url, init] = stub.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`${AUTHORITY}/auth/revoke`)
    const body = new URLSearchParams(init.body as string)
    expect(body.get("client_id")).toBe(CLIENT_ID)
    expect(body.get("token")).toBe("rt_to_kill")
    expect(body.get("token_type_hint")).toBe("refresh_token")
  })

  it("resolves on a 200 even for an unknown token (RFC 7009 §2.2)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200 }))
    await expect(revokeToken(AUTHORITY, CLIENT_ID, "unknown")).resolves.toBeUndefined()
  })

  it("throws on a non-2xx revocation response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }))
    await expect(revokeToken(AUTHORITY, CLIENT_ID, "rt")).rejects.toThrow(/HTTP 500/)
  })

  it("wraps a fetch rejection in NetworkError", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")))
    await expect(revokeToken(AUTHORITY, CLIENT_ID, "rt")).rejects.toBeInstanceOf(NetworkError)
  })
})
