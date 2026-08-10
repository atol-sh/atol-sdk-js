/**
 * Unit tests for the renewal-error classification layer. Every OAuth
 * error code we recognize is pinned to its action, and the default
 * branches (unknown codes, unknown Error subclasses) are pinned to
 * `Surface` -- that conservative default is the load-bearing property.
 */
import { describe, it, expect } from "vitest"
import {
  LoginRequiredError,
  NetworkError,
  OAuthProtocolError,
  RecoveryAction,
  backoffDelay,
  classifyRenewalError,
} from "../../src/oidc/token-recovery"

describe("classifyRenewalError -- terminal auth errors", () => {
  it.each([
    "invalid_grant",
    "invalid_request",
    "invalid_client",
    "unauthorized_client",
    "login_required",
    "consent_required",
    "interaction_required",
  ])("%s -> ForceReauth", (code) => {
    expect(classifyRenewalError(new OAuthProtocolError(code, "msg"))).toBe(
      RecoveryAction.ForceReauth,
    )
  })

  it("LoginRequiredError -> ForceReauth (subclass path)", () => {
    expect(classifyRenewalError(new LoginRequiredError("x"))).toBe(
      RecoveryAction.ForceReauth,
    )
  })
})

describe("classifyRenewalError -- transient errors", () => {
  it.each(["server_error", "temporarily_unavailable"])("%s -> Retry", (code) => {
    expect(classifyRenewalError(new OAuthProtocolError(code))).toBe(
      RecoveryAction.Retry,
    )
  })

  it("NetworkError -> Retry", () => {
    expect(classifyRenewalError(new NetworkError("fetch failed"))).toBe(
      RecoveryAction.Retry,
    )
  })

})

describe("classifyRenewalError -- surface", () => {
  it.each([
    "invalid_scope",
    "unsupported_grant_type",
    "unsupported_response_type",
  ])("%s -> Surface", (code) => {
    expect(classifyRenewalError(new OAuthProtocolError(code))).toBe(
      RecoveryAction.Surface,
    )
  })

  it("unknown OAuth code -> Surface (conservative default)", () => {
    const error = new OAuthProtocolError("mystery_error")
    expect(error.code).toBe("invalid_response")
    expect(classifyRenewalError(error)).toBe(
      RecoveryAction.Surface,
    )
  })

  it("plain Error -> Surface (not auto-retryable)", () => {
    expect(classifyRenewalError(new Error("something"))).toBe(
      RecoveryAction.Surface,
    )
  })

  it('[R48] TypeError -> Surface because transport failures must be normalized', () => {
    expect(classifyRenewalError(new TypeError('Invalid URL'))).toBe(RecoveryAction.Surface)
    expect(classifyRenewalError(new TypeError('WebCrypto is unavailable'))).toBe(
      RecoveryAction.Surface,
    )
  })

  it("non-error value -> Surface", () => {
    expect(classifyRenewalError("string thrown")).toBe(RecoveryAction.Surface)
    expect(classifyRenewalError(null)).toBe(RecoveryAction.Surface)
    expect(classifyRenewalError(undefined)).toBe(RecoveryAction.Surface)
  })
})

describe("backoffDelay", () => {
  it("grows exponentially with the attempt counter", () => {
    const fiftyPercent = () => 0.5
    const d0 = backoffDelay(0, fiftyPercent)
    const d1 = backoffDelay(1, fiftyPercent)
    const d2 = backoffDelay(2, fiftyPercent)
    const d3 = backoffDelay(3, fiftyPercent)
    expect(d1).toBe(d0 * 2)
    expect(d2).toBe(d1 * 2)
    expect(d3).toBe(d2 * 2)
  })

  it("never exceeds the 30s cap", () => {
    expect(backoffDelay(100, () => 0.9999)).toBeLessThan(30_000)
  })

  it("bottoms out at 0 with rand=0", () => {
    expect(backoffDelay(5, () => 0)).toBe(0)
  })

  it("treats negative attempts as 0", () => {
    expect(backoffDelay(-10, () => 0.5)).toBe(backoffDelay(0, () => 0.5))
  })
})

describe("OAuthProtocolError / LoginRequiredError / NetworkError shape", () => {
  it("OAuthProtocolError carries only the closed error code", () => {
    const err = new OAuthProtocolError("invalid_grant", "token gone")
    expect(err.code).toBe("invalid_grant")
    expect(err).not.toHaveProperty("description")
    expect(err.message).toBe("OAuth protocol error: invalid_grant")
    expect(err.name).toBe("OAuthProtocolError")
  })

  it("OAuthProtocolError uses a stable code-derived message", () => {
    expect(new OAuthProtocolError("server_error").message).toBe(
      "OAuth protocol error: server_error",
    )
  })

  it("LoginRequiredError is both OAuthProtocolError and LoginRequiredError", () => {
    const err = new LoginRequiredError("session gone")
    expect(err).toBeInstanceOf(LoginRequiredError)
    expect(err).toBeInstanceOf(OAuthProtocolError)
    expect(err.code).toBe("login_required")
    expect(err.name).toBe("LoginRequiredError")
  })

  it("forgets arbitrary descriptions, names, and causes", () => {
    const sentinel = "sentinel-secret-token"
    const protocol = new OAuthProtocolError(sentinel, sentinel)
    const network = new NetworkError(
      "network request failed",
      new Error(sentinel),
    )

    expect(protocol.code).toBe("invalid_response")
    expect(protocol).not.toHaveProperty("description")
    expect(network).not.toHaveProperty("cause")
    expect(network.name).toBe("NetworkError")
    for (const error of [protocol, network]) {
      expect(JSON.stringify(error)).not.toContain(sentinel)
      expect(String(error)).not.toContain(sentinel)
      expect(error.stack).not.toContain(sentinel)
      expect(Object.values(error)).not.toContain(sentinel)
    }
  })
})
