import { describe, it, expect, vi, afterEach, afterAll, beforeAll } from "vitest"
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
      source: iframe.contentWindow,
    }),
  )
}

const AUTHORITY = "http://atol.localhost:9080"
const BASE_OPTS = {
  authority: AUTHORITY,
  clientId: "atol_kid_test",
  redirectUri: "http://app.localhost:3000/callback",
  scope: "openid profile email",
}
const ORGANIZATION_ID = "01KV4BNVMVG66Q04WGMMD6W4PB"

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
    const nonce = url.searchParams.get("nonce")!
    expect(nonce).toMatch(/^[0-9a-f]{64}$/)
    const challenge = url.searchParams.get("code_challenge")!
    expect(challenge).not.toMatch(/[+/=]/) // base64url, unpadded

    // Complete the flow and confirm the returned verifier matches the
    // challenge we saw (S256(verifier) === challenge).
    postAuthResponse(iframe, AUTHORITY, { code: "authcode", state })
    const result = await p
    expect(await s256(result.codeVerifier)).toBe(challenge)
    expect(result.nonce).toBe(nonce)
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

  it("[R10] binds a requested organization to the prompt=none authorization", async () => {
    type OrganizationAuthorizeOptions = Parameters<typeof silentAuthorize>[0] & {
      organizationId: string
    }
    const options: OrganizationAuthorizeOptions = {
      ...BASE_OPTS,
      timeoutMs: 500,
      organizationId: ORGANIZATION_ID,
    }
    const p = silentAuthorize(options)
    const iframe = await nextAppendedIframe()
    const url = new URL(iframe.src)
    postAuthResponse(iframe, AUTHORITY, {
      code: "organization-code",
      state: url.searchParams.get("state"),
    })
    await p

    expect(url.searchParams.get("prompt")).toBe("none")
    expect(url.searchParams.get("atol_org_id")).toBe(ORGANIZATION_ID)
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

  it("[R28] isolates concurrent iframe responses by their source window", async () => {
    const first = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const firstIframe = await nextAppendedIframe()
    const firstState = new URL(firstIframe.src).searchParams.get("state")
    const firstOutcome = first.then(
      (value) => ({ status: "fulfilled" as const, value }),
      (error: unknown) => ({ status: "rejected" as const, error }),
    )

    const second = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const secondIframe = await nextAppendedIframe()
    const secondState = new URL(secondIframe.src).searchParams.get("state")

    postAuthResponse(secondIframe, AUTHORITY, {
      code: "second-code",
      state: secondState,
    })
    await expect(second).resolves.toMatchObject({ code: "second-code" })

    let firstSettled = false
    void firstOutcome.then(() => {
      firstSettled = true
    })
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(firstSettled).toBe(false)

    postAuthResponse(firstIframe, AUTHORITY, {
      code: "first-code",
      state: firstState,
    })
    await expect(firstOutcome).resolves.toMatchObject({
      status: "fulfilled",
      value: { code: "first-code" },
    })
  })
})

describe("silentAuthorize -- error mapping + origin/state checks", () => {
  afterEach(() => {
    document.body.innerHTML = ""
  })

  it("raises LoginRequiredError on login_required response", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const iframe = await nextAppendedIframe()
    postAuthResponse(iframe, AUTHORITY, {
      error: "login_required",
      error_description: "session expired",
      state: new URL(iframe.src).searchParams.get("state"),
    })
    await expect(p).rejects.toBeInstanceOf(LoginRequiredError)
  })

  it("raises LoginRequiredError on consent_required", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const iframe = await nextAppendedIframe()
    postAuthResponse(iframe, AUTHORITY, {
      error: "consent_required",
      state: new URL(iframe.src).searchParams.get("state"),
    })
    await expect(p).rejects.toBeInstanceOf(LoginRequiredError)
  })

  it("[R34] raises LoginRequiredError on account_selection_required", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const iframe = await nextAppendedIframe()
    postAuthResponse(iframe, AUTHORITY, {
      error: "account_selection_required",
      state: new URL(iframe.src).searchParams.get("state"),
    })
    await expect(p).rejects.toBeInstanceOf(LoginRequiredError)
  })

  it("raises a non-login Error on server_error", async () => {
    const p = silentAuthorize({ ...BASE_OPTS, timeoutMs: 500 })
    const iframe = await nextAppendedIframe()
    postAuthResponse(iframe, AUTHORITY, {
      error: "server_error",
      state: new URL(iframe.src).searchParams.get("state"),
    })
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
  afterEach(() => {
    document.body.innerHTML = ""
  })

  it("does not retry a terminal authorize response", async () => {
    const createElement = vi.spyOn(document, "createElement")
    const p = silentAuthorizeWithRetry({ ...BASE_OPTS, timeoutMs: 50 }, 3)
    const iframe = await nextAppendedIframe()
    postAuthResponse(iframe, AUTHORITY, {
      error: "login_required",
      state: new URL(iframe.src).searchParams.get("state"),
    })

    await expect(p).rejects.toBeInstanceOf(LoginRequiredError)
    expect(createElement.mock.calls.filter(([tag]) => tag === "iframe")).toHaveLength(1)
  })

  it("[R34] does not retry a state-integrity failure", async () => {
    const createElement = vi.spyOn(document, "createElement")
    const p = silentAuthorizeWithRetry({ ...BASE_OPTS, timeoutMs: 30 }, 3)
    const iframe = await nextAppendedIframe()
    postAuthResponse(iframe, AUTHORITY, {
      code: "attacker-code",
      state: "wrong-state",
    })

    const error = await p.catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toMatch(/state mismatch/)
    expect(createElement.mock.calls.filter(([tag]) => tag === "iframe")).toHaveLength(1)
  })

  it("retries a transient server response and returns the later grant", async () => {
    const createElement = vi.spyOn(document, "createElement")
    const p = silentAuthorizeWithRetry({ ...BASE_OPTS, timeoutMs: 500 }, 3)
    const first = await nextAppendedIframe()
    postAuthResponse(first, AUTHORITY, {
      error: "server_error",
      state: new URL(first.src).searchParams.get("state"),
    })

    await vi.waitFor(() => {
      expect(document.querySelector("iframe")).not.toBeNull()
    }, { timeout: 400 })
    const second = document.querySelector("iframe") as HTMLIFrameElement
    const secondState = new URL(second.src).searchParams.get("state")
    postAuthResponse(second, AUTHORITY, { code: "recovered", state: secondState })

    await expect(p).resolves.toMatchObject({ code: "recovered", state: secondState })
    expect(createElement.mock.calls.filter(([tag]) => tag === "iframe")).toHaveLength(2)
  })
})
