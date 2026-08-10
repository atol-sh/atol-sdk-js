/**
 * Token-endpoint behavior: exchangeCode, refreshTokenGrant, and
 * revokeToken. Covers request shaping, OAuth error mapping (classified via
 * token-recovery), DPoP nonce challenge retry, and revocation.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import {
  exchangeCode,
  parseDPoPNonceHeader,
  refreshTokenGrant,
  revokeToken,
  LoginRequiredError,
} from "../../src/oidc/silent-renew"
import {
  AuthorizationCodeExchangeUncertainError,
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

function errorObservables(error: Error): string {
  const ownValues = Object.getOwnPropertyNames(error).map(
    (name) => String(Reflect.get(error, name)),
  )
  return [
    error.name,
    error.message,
    error.stack ?? "",
    JSON.stringify(error),
    ...ownValues,
  ].join("\n")
}

beforeEach(() => vi.restoreAllMocks())
afterEach(() => vi.unstubAllGlobals())

describe("parseDPoPNonceHeader", () => {
  it("retains one RFC 9449 NQCHAR value exactly", () => {
    const nonce = "eyJ7S_zG.eyJH0-Z.HX4w-7v"
    expect(
      parseDPoPNonceHeader({ get: () => nonce }),
    ).toBe(nonce)
    expect(parseDPoPNonceHeader({ get: () => null })).toBeUndefined()
  })

  it("rejects comma-joined duplicate fields", () => {
    const headers = new Headers()
    headers.append("DPoP-Nonce", "first-nonce")
    headers.append("DPoP-Nonce", "second-nonce")
    expect(headers.get("DPoP-Nonce")).toContain(",")
    expect(() => parseDPoPNonceHeader(headers)).toThrow(
      /server nonce header is invalid/,
    )
  })

  it.each([
    ["empty", ""],
    ["leading whitespace", " nonce"],
    ["trailing whitespace", "nonce "],
    ["embedded whitespace", "nonce value"],
    ["tab", "nonce\tvalue"],
    ["control", "nonce\u0001value"],
    ["quote", 'nonce"value'],
    ["backslash", "nonce\\value"],
    ["non-ASCII", "nonce-\u00E9"],
    ["oversized", "n".repeat(513)],
  ])("rejects %s values", (_name, nonce) => {
    expect(() =>
      parseDPoPNonceHeader({ get: () => nonce }),
    ).toThrow(/server nonce header is invalid/)
  })
})

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
        text: async () =>
          JSON.stringify({
            access_token: "at",
            token_type: "DPoP",
            expires_in: 60,
          }),
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

  it('classifies a malformed success nonce as uncertain after dispatch without retaining it', async () => {
    const sentinel = 'sentinel-secret-invalid-dpop-nonce'
    const signer = {
      signProof: vi.fn().mockResolvedValue('proof'),
    }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: 'at',
            token_type: 'DPoP',
            expires_in: 60,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'DPoP-Nonce': `valid,${sentinel}`,
            },
          },
        ),
      ),
    )

    const error = await exchangeCode(
      AUTHORITY,
      CLIENT_ID,
      'code',
      'https://app/cb',
      'verifier',
      signer,
    ).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(
      AuthorizationCodeExchangeUncertainError,
    )
    expect(error).toMatchObject({
      code: 'authorization_code_exchange_uncertain',
    })
    expect(error).not.toHaveProperty('cause')
    if (!(error instanceof Error)) {
      throw new Error('expected an Error')
    }
    expect(error.message).toBe(
      'token exchange response is incomplete',
    )
    expect(errorObservables(error)).not.toContain(sentinel)
  })

  it('classifies a rejected post-dispatch transport as a closed uncertain exchange', async () => {
    const sentinel = 'sentinel-secret-dispatched-token-transport'
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(
        new TypeError(
          `fetch failed for https://id.test/token?code=${sentinel}`,
        ),
      ),
    )

    const error = await exchangeCode(
      AUTHORITY,
      CLIENT_ID,
      sentinel,
      `https://app.test/cb?credential=${sentinel}`,
      sentinel,
    ).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(
      AuthorizationCodeExchangeUncertainError,
    )
    expect(error).toMatchObject({
      code: 'authorization_code_exchange_uncertain',
      message: 'token exchange response is incomplete',
    })
    expect(error).not.toHaveProperty('cause')
    if (!(error instanceof Error)) {
      throw new Error('expected an Error')
    }
    expect(errorObservables(error)).not.toContain(sentinel)
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

  it('forgets credentials and URL query data from a rejected DPoP signer', async () => {
    const sentinel = 'sentinel-secret-dpop-credential'
    const fetchStub = vi.fn()
    vi.stubGlobal('fetch', fetchStub)
    const signer = {
      signProof: vi.fn().mockRejectedValue(
        new Error(
          `proof failed for https://api.test/resource?token=${sentinel}`,
        ),
      ),
    }

    const error = await exchangeCode(
      AUTHORITY,
      CLIENT_ID,
      sentinel,
      `https://app.test/cb?credential=${sentinel}`,
      sentinel,
      signer,
    ).catch((caught: unknown) => caught)

    expect(fetchStub).not.toHaveBeenCalled()
    expect(error).toBeInstanceOf(Error)
    expect(error).not.toHaveProperty('cause')
    if (!(error instanceof Error)) {
      throw new Error('expected an Error')
    }
    expect(errorObservables(error)).not.toContain(sentinel)
    expect(error.message).toBe(
      'token exchange DPoP proof could not be created',
    )
  })

  it('[R30] reuses the latest successful server nonce on the next token request', async () => {
    const signer = { signProof: vi.fn().mockResolvedValue('proof') }
    const stub = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'DPoP-Nonce': 'nonce-for-next-request' }),
        text: async () =>
          JSON.stringify({
            access_token: 'at-1',
            token_type: 'DPoP',
            expires_in: 60,
          }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        text: async () =>
          JSON.stringify({
            access_token: 'at-2',
            token_type: 'DPoP',
            expires_in: 60,
          }),
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

  it('rejects a combined challenge nonce without retrying', async () => {
    const headers = new Headers()
    headers.append('DPoP-Nonce', 'first-nonce')
    headers.append('DPoP-Nonce', 'second-nonce')
    const signer = { signProof: vi.fn().mockResolvedValue('proof') }
    const stub = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      headers,
      clone() {
        return this
      },
      text: async () => JSON.stringify({ error: 'use_dpop_nonce' }),
    })
    vi.stubGlobal('fetch', stub)

    await expect(
      exchangeCode(
        AUTHORITY,
        CLIENT_ID,
        'code',
        'https://app/cb',
        'verifier',
        signer,
      ),
    ).rejects.toBeInstanceOf(
      AuthorizationCodeExchangeUncertainError,
    )
    expect(stub).toHaveBeenCalledTimes(1)
    expect(signer.signProof).toHaveBeenCalledTimes(1)
  })

  it('does not replace a cached nonce with a malformed success header', async () => {
    const signer = { signProof: vi.fn().mockResolvedValue('proof') }
    const stub = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'DPoP-Nonce': 'stable-nonce' }),
        text: async () =>
          JSON.stringify({
            access_token: 'at-1',
            token_type: 'DPoP',
            expires_in: 60,
          }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { get: () => 'attacker, replacement' },
        text: async () =>
          JSON.stringify({
            access_token: 'at-2',
            token_type: 'DPoP',
            expires_in: 60,
          }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        text: async () =>
          JSON.stringify({
            access_token: 'at-3',
            token_type: 'DPoP',
            expires_in: 60,
          }),
      })
    vi.stubGlobal('fetch', stub)

    await exchangeCode(
      AUTHORITY,
      CLIENT_ID,
      'code-1',
      'https://app/cb',
      'verifier-1',
      signer,
    )
    await expect(
      exchangeCode(
        AUTHORITY,
        CLIENT_ID,
        'code-2',
        'https://app/cb',
        'verifier-2',
        signer,
      ),
    ).rejects.toBeInstanceOf(
      AuthorizationCodeExchangeUncertainError,
    )
    await exchangeCode(
      AUTHORITY,
      CLIENT_ID,
      'code-3',
      'https://app/cb',
      'verifier-3',
      signer,
    )

    expect(signer.signProof).toHaveBeenNthCalledWith(
      3,
      'POST',
      `${AUTHORITY}/auth/token`,
      { nonce: 'stable-nonce' },
    )
  })
})

const malformedTokenSuccessBodies: ReadonlyArray<
  readonly [string, string]
> = [
  [
    "duplicate member",
    '{"access_token":"sentinel-secret-first","access_token":"sentinel-secret-second","token_type":"bearer","expires_in":60}',
  ],
  [
    "unexpected member",
    JSON.stringify({
      access_token: "sentinel-secret-access-token",
      token_type: "bearer",
      expires_in: 60,
      debug: "sentinel-secret-debug",
    }),
  ],
  [
    "missing required member",
    JSON.stringify({
      access_token: "sentinel-secret-access-token",
      token_type: "bearer",
    }),
  ],
  [
    "empty access token",
    JSON.stringify({
      access_token: "",
      token_type: "bearer",
      expires_in: 60,
    }),
  ],
  [
    "unknown token type",
    JSON.stringify({
      access_token: "sentinel-secret-access-token",
      token_type: "sentinel-secret-token-type",
      expires_in: 60,
    }),
  ],
  [
    "zero lifetime",
    JSON.stringify({
      access_token: "sentinel-secret-access-token",
      token_type: "bearer",
      expires_in: 0,
    }),
  ],
  [
    "fractional lifetime",
    JSON.stringify({
      access_token: "sentinel-secret-access-token",
      token_type: "bearer",
      expires_in: 1.5,
    }),
  ],
  [
    "excessive lifetime",
    JSON.stringify({
      access_token: "sentinel-secret-access-token",
      token_type: "bearer",
      expires_in: 86_401,
    }),
  ],
  [
    "wrong optional type",
    JSON.stringify({
      access_token: "sentinel-secret-access-token",
      token_type: "bearer",
      expires_in: 60,
      refresh_token: { secret: "sentinel-secret-refresh-token" },
    }),
  ],
  ["oversized body", "x".repeat(32 * 1024 + 1)],
]

describe("shared token success validation", () => {
  it.each(malformedTokenSuccessBodies)(
    "rejects a %s before either grant adopts it",
    async (_name, body) => {
      mockFetchOnce({ ok: true, body })
      const exchangeError = await exchangeCode(
        AUTHORITY,
        CLIENT_ID,
        "code",
        "https://app/cb",
        "verifier",
      ).catch((error: unknown) => error)
      expect(exchangeError).toBeInstanceOf(
        AuthorizationCodeExchangeUncertainError,
      )
      if (!(exchangeError instanceof Error)) {
        throw new Error("expected an Error")
      }
      expect(exchangeError).not.toHaveProperty("cause")
      expect(errorObservables(exchangeError)).not.toContain(
        "sentinel-secret",
      )

      mockFetchOnce({ ok: true, body })
      const refreshError = await refreshTokenGrant(
        AUTHORITY,
        CLIENT_ID,
        REFRESH,
      ).catch((error: unknown) => error)
      expect(refreshError).toBeInstanceOf(OAuthProtocolError)
      expect(refreshError).toMatchObject({
        code: "invalid_response",
      })
      expect(classifyRenewalError(refreshError)).toBe(
        RecoveryAction.Surface,
      )
      if (!(refreshError instanceof Error)) {
        throw new Error("expected an Error")
      }
      expect(errorObservables(refreshError)).not.toContain(
        "sentinel-secret",
      )
    },
  )
})

describe("refreshTokenGrant", () => {
  it('maps a malformed response nonce to a closed invalid_response error', async () => {
    const sentinel = 'sentinel-secret-refresh-dpop-nonce'
    const signer = {
      signProof: vi.fn().mockResolvedValue('proof'),
    }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: 'at',
            token_type: 'DPoP',
            expires_in: 60,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'DPoP-Nonce': `valid,${sentinel}`,
            },
          },
        ),
      ),
    )

    const error = await refreshTokenGrant(
      AUTHORITY,
      CLIENT_ID,
      REFRESH,
      undefined,
      undefined,
      signer,
    ).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(OAuthProtocolError)
    expect(error).toMatchObject({ code: 'invalid_response' })
    expect(error).not.toHaveProperty('cause')
    if (!(error instanceof Error)) {
      throw new Error('expected an Error')
    }
    expect(errorObservables(error)).not.toContain(sentinel)
  })

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
    const sentinel = "sentinel-secret-fetch-cause"
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValueOnce(new TypeError(sentinel)),
    )
    const error = await refreshTokenGrant(
      AUTHORITY,
      CLIENT_ID,
      REFRESH,
    ).catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(NetworkError)
    expect(classifyRenewalError(error)).toBe(RecoveryAction.Retry)
    expect(error).not.toHaveProperty("cause")
    if (!(error instanceof Error)) {
      throw new Error("expected an Error")
    }
    expect(errorObservables(error)).not.toContain(sentinel)
  })

  it("maps 429 (rate limited) to a transient error (Retry), not a sign-out", async () => {
    mockFetchOnce({ ok: false, status: 429, body: { error: "slow_down" } })
    const err = await refreshTokenGrant(AUTHORITY, CLIENT_ID, REFRESH).catch((e) => e)
    expect((err as OAuthProtocolError).code).toBe("temporarily_unavailable")
    expect(classifyRenewalError(err)).toBe(RecoveryAction.Retry)
  })

  it("retains a known code without the server description, URI, or body", async () => {
    const sentinel = "sentinel-secret-oauth-detail"
    mockFetchOnce({
      ok: false,
      status: 400,
      body: {
        error: "invalid_grant",
        error_description: sentinel,
        error_uri: `https://auth.atol.test/error?detail=${sentinel}`,
      },
    })

    const error = await refreshTokenGrant(
      AUTHORITY,
      CLIENT_ID,
      REFRESH,
    ).catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(OAuthProtocolError)
    expect(error).toMatchObject({ code: "invalid_grant" })
    expect(error).not.toHaveProperty("description")
    expect(error).not.toHaveProperty("cause")
    if (!(error instanceof Error)) {
      throw new Error("expected an Error")
    }
    expect(errorObservables(error)).not.toContain(sentinel)
  })

  it.each([
    [
      "unknown server code",
      JSON.stringify({
        error: "sentinel-secret-server-code",
        error_description: "sentinel-secret-description",
      }),
    ],
    [
      "duplicate error member",
      '{"error":"invalid_grant","error":"sentinel-secret-server-code"}',
    ],
    [
      "unexpected error member",
      JSON.stringify({
        error: "invalid_grant",
        error_description: "generic",
        debug: "sentinel-secret-debug",
      }),
    ],
    [
      "wrong description type",
      JSON.stringify({
        error: "invalid_grant",
        error_description: {
          detail: "sentinel-secret-description",
        },
      }),
    ],
    ["oversized error body", "x".repeat(4 * 1024 + 1)],
  ])(
    "maps a %s to one closed Surface-class error",
    async (_name, body) => {
      mockFetchOnce({ ok: false, status: 400, body })
      const error = await refreshTokenGrant(
        AUTHORITY,
        CLIENT_ID,
        REFRESH,
      ).catch((caught: unknown) => caught)

      expect(error).toBeInstanceOf(OAuthProtocolError)
      expect(error).toMatchObject({ code: "invalid_response" })
      expect(classifyRenewalError(error)).toBe(
        RecoveryAction.Surface,
      )
      if (!(error instanceof Error)) {
        throw new Error("expected an Error")
      }
      expect(errorObservables(error)).not.toContain(
        "sentinel-secret",
      )
    },
  )

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
        text: async () =>
          JSON.stringify({
            access_token: "at",
            token_type: "DPoP",
            expires_in: 60,
          }),
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
      body: { access_token: "at", token_type: "DPoP", expires_in: 60 },
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
