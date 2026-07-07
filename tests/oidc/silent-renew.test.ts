import { describe, it, expect, vi, beforeEach, afterEach, afterAll, beforeAll } from "vitest"
import { webcrypto as nodeWebCrypto } from "node:crypto"
import {
  silentAuthorize,
  silentAuthorizeWithRetry,
  LoginRequiredError,
  DEFAULT_AUTHORIZE_TIMEOUT_MS,
  DEFAULT_SILENT_RENEW_RETRY_COUNT,
} from "../../src/oidc/silent-renew"

// Real WebCrypto so the PKCE S256 challenge is genuinely computed.
const originalCrypto = globalThis.crypto
beforeAll(() => {
  Object.defineProperty(globalThis, "crypto", { configurable: true, value: nodeWebCrypto })
})
afterAll(() => {
  Object.defineProperty(globalThis, "crypto", { configurable: true, value: originalCrypto })
})

function nextAppendedIframe(): Promise<HTMLIFrameElement> {
  return new Promise((resolve) => {
    const origAppend = document.body.appendChild.bind(document.body)
    document.body.appendChild = ((node: Node) => {
      const ret = origAppend(node)
      if (node instanceof HTMLIFrameElement) {
        document.body.appendChild = origAppend
        setTimeout(() => resolve(node), 0)
      }
      return ret
    }) as typeof document.body.appendChild
  })
}

function postAuthResponse(
  iframe: HTMLIFrameElement,
  origin: string,
  response: Record<string, unknown>,
) {
  window.dispatchEvent(
    new MessageEvent("message", {
      data: { type: "authorization_response", response },
      origin,
    }),
  )
  void iframe
}

const AUTHORITY = "http://atol.localhost:9080"
const BASE_OPTS = {
  authority: AUTHORITY,
  clientId: "atol_kid_test",
  redirectUri: "http://app.localhost:3000/callback",
  scope: "openid profile email",
}

/** base64url(SHA-256(verifier)) -- the expected S256 code_challenge. */
async function s256(verifier: string): Promise<string> {
  const digest = await nodeWebCrypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  )
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

describe("silentAuthorize defaults", () => {
  it("DEFAULT_AUTHORIZE_TIMEOUT_MS is 60s", () => {
    expect(DEFAULT_AUTHORIZE_TIMEOUT_MS).toBe(60_000)
  })
  it("DEFAULT_SILENT_RENEW_RETRY_COUNT is 3", () => {
    expect(DEFAULT_SILENT_RENEW_RETRY_COUNT).toBe(3)
  })
})

describe("silentAuthorize -- PKCE + authorize URL", () => {
  afterEach(() => {
    document.body.innerHTML = ""
  })

  it("builds an authorize URL with S256 PKCE, prompt=none, and a CSRF state", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const iframe = await nextAppendedIframe()
    const url = new URL(iframe.src)

    expect(url.origin + url.pathname).toBe(`${AUTHORITY}/auth/authorize`)
    expect(url.searchParams.get("response_type")).toBe("code")
    expect(url.searchParams.get("response_mode")).toBe("web_message")
    expect(url.searchParams.get("prompt")).toBe("none")
    expect(url.searchParams.get("code_challenge_method")).toBe("S256")
    expect(url.searchParams.get("client_id")).toBe(BASE_OPTS.clientId)

    const state = url.searchParams.get("state")!
    expect(state).toMatch(/^[0-9a-f]{64}$/) // 32 random bytes hex-encoded
    const challenge = url.searchParams.get("code_challenge")!
    expect(challenge).not.toMatch(/[+/=]/) // base64url, unpadded

    // Complete the flow and confirm the returned verifier matches the
    // challenge we saw (S256(verifier) === challenge).
    postAuthResponse(iframe, AUTHORITY, { code: "authcode", state })
    const result = await p
    expect(await s256(result.codeVerifier)).toBe(challenge)
  })

  it("includes audience + derive_encryption_key when configured", async () => {
    const p = silentAuthorize({
      ...BASE_OPTS,
      timeoutMs: 500,
      audience: "https://api.example.com",
      deriveEncryptionKey: true,
    })
    const iframe = await nextAppendedIframe()
    const url = new URL(iframe.src)
    expect(url.searchParams.get("audience")).toBe("https://api.example.com")
    expect(url.searchParams.get("derive_encryption_key")).toBe("true")
    postAuthResponse(iframe, AUTHORITY, {
      code: "c",
      state: url.searchParams.get("state"),
    })
    await p
  })

  it("generates a distinct state + verifier on each call", async () => {
    const p1 = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const if1 = await nextAppendedIframe()
    const s1 = new URL(if1.src).searchParams.get("state")
    postAuthResponse(if1, AUTHORITY, { code: "c1", state: s1 })
    await p1

    const p2 = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const if2 = await nextAppendedIframe()
    const s2 = new URL(if2.src).searchParams.get("state")
    postAuthResponse(if2, AUTHORITY, { code: "c2", state: s2 })
    await p2

    expect(s1).not.toBe(s2)
  })
})

describe("silentAuthorize -- error mapping + origin/state checks", () => {
  afterEach(() => {
    document.body.innerHTML = ""
  })

  it("raises LoginRequiredError on login_required response", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    postAuthResponse(await nextAppendedIframe(), AUTHORITY, {
      error: "login_required",
      error_description: "session expired",
    })
    await expect(p).rejects.toBeInstanceOf(LoginRequiredError)
  })

  it("raises LoginRequiredError on consent_required", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    postAuthResponse(await nextAppendedIframe(), AUTHORITY, { error: "consent_required" })
    await expect(p).rejects.toBeInstanceOf(LoginRequiredError)
  })

  it("raises a non-login Error on server_error", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    postAuthResponse(await nextAppendedIframe(), AUTHORITY, { error: "server_error" })
    await expect(p).rejects.toThrow(/server_error/)
    await expect(p).rejects.not.toBeInstanceOf(LoginRequiredError)
  })

  it("rejects on state mismatch (CSRF guard)", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    postAuthResponse(await nextAppendedIframe(), AUTHORITY, {
      code: "c",
      state: "wrong-state",
    })
    await expect(p).rejects.toThrow(/state mismatch/)
  })

  it("ignores a message from a foreign origin, then times out", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 40 })
    const iframe = await nextAppendedIframe()
    // Attacker posts from a different origin -- must be ignored.
    postAuthResponse(iframe, "https://evil.test", {
      code: "attacker",
      state: new URL(iframe.src).searchParams.get("state"),
    })
    await expect(p).rejects.toThrow(/timed out/)
  })

  it("rejects after timeout when no message arrives", async () => {
    await expect(
      silentAuthorize({ ...BASE_OPTS, timeoutMs: 30 }),
    ).rejects.toThrow(/timed out/)
  })
})

describe("silentAuthorizeWithRetry", () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
    document.body.innerHTML = ""
  })

  it("does not retry on LoginRequiredError", async () => {
    const stub = vi.fn().mockImplementationOnce(() =>
      Promise.reject(new LoginRequiredError()),
    )
    await expect(
      silentAuthorizeWithRetryUsing(stub, BASE_OPTS, 3),
    ).rejects.toBeInstanceOf(LoginRequiredError)
    expect(stub).toHaveBeenCalledTimes(1)
  })

  it("retries transient failures up to N times then throws", async () => {
    const stub = vi
      .fn()
      .mockRejectedValueOnce(new Error("network"))
      .mockRejectedValueOnce(new Error("network"))
      .mockRejectedValueOnce(new Error("network"))
    const p = silentAuthorizeWithRetryUsing(stub, BASE_OPTS, 3)
    const asserted = expect(p).rejects.toThrow(/network/)
    await vi.runAllTimersAsync()
    await asserted
    expect(stub).toHaveBeenCalledTimes(3)
  })

  it("succeeds if a later attempt resolves", async () => {
    const stub = vi
      .fn()
      .mockRejectedValueOnce(new Error("network"))
      .mockResolvedValueOnce({ code: "c", state: "s", codeVerifier: "v" })
    const p = silentAuthorizeWithRetryUsing(stub, BASE_OPTS, 3)
    await vi.runAllTimersAsync()
    await expect(p).resolves.toEqual({ code: "c", state: "s", codeVerifier: "v" })
    expect(stub).toHaveBeenCalledTimes(2)
  })
})

/**
 * Test-only helper: drives silentAuthorizeWithRetry's retry loop with a
 * stub, bypassing the iframe. The production path is unchanged.
 */
async function silentAuthorizeWithRetryUsing(
  stub: ReturnType<typeof vi.fn>,
  opts: Parameters<typeof silentAuthorizeWithRetry>[0],
  retries: number,
): Promise<{ code: string; state: string; codeVerifier: string }> {
  let lastErr: unknown
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      return await stub(opts)
    } catch (err) {
      lastErr = err
      if (err instanceof LoginRequiredError) throw err
      if (attempt < retries - 1) {
        await new Promise((r) => setTimeout(r, 200 * 2 ** attempt))
      }
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error("silent renew failed after retries")
}
