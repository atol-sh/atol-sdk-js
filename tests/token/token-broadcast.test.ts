import { afterEach, describe, expect, it, vi } from "vitest"
import {
  createTokenBroadcast,
  hasBroadcastSupport,
  type BroadcastMessage,
} from "../../src/token/token-broadcast"

/**
 * jsdom v16+ ships BroadcastChannel, so these tests use the real thing
 * wherever possible. The "no-op" test uninstalls it to exercise the
 * fallback path. The type-guard tests assert that only well-formed
 * token-rotated / session-expired messages ever reach a subscriber -- the
 * first line of defense against a forged same-origin broadcast (the
 * signature check lives in the browser auth client, tested separately).
 */

describe("createTokenBroadcast", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("detects native BroadcastChannel support", () => {
    expect(hasBroadcastSupport()).toBe(true)
  })

  it("delivers published messages to subscribers on the same channel", async () => {
    const pub = createTokenBroadcast("atol:test:delivery")
    const sub = createTokenBroadcast("atol:test:delivery")
    const received: BroadcastMessage[] = []
    const unsubscribe = sub.subscribe((m) => received.push(m))

    pub.publish({
      type: "token-rotated",
      accessToken: "at",
      idToken: "id",
      refreshToken: "rt",
      expiresAt: 123_456,
      sentAt: 123_000,
    })
    await new Promise((r) => setTimeout(r, 20))

    expect(received).toHaveLength(1)
    expect(received[0]).toMatchObject({
      type: "token-rotated",
      accessToken: "at",
      refreshToken: "rt",
    })

    unsubscribe()
    pub.close()
    sub.close()
  })

  it("does not deliver messages across different channel names", async () => {
    const a = createTokenBroadcast("atol:test:A")
    const b = createTokenBroadcast("atol:test:B")
    const received: BroadcastMessage[] = []
    const unsubscribe = b.subscribe((m) => received.push(m))

    a.publish({ type: "token-rotated", accessToken: "x", expiresAt: 1, sentAt: 0 })
    await new Promise((r) => setTimeout(r, 20))

    expect(received).toHaveLength(0)
    unsubscribe()
    a.close()
    b.close()
  })

  it("delivers session-expired broadcasts", async () => {
    const pub = createTokenBroadcast("atol:test:logout")
    const sub = createTokenBroadcast("atol:test:logout")
    const received: BroadcastMessage[] = []
    const unsubscribe = sub.subscribe((m) => received.push(m))

    pub.publish({ type: "session-expired", sentAt: Date.now() })
    await new Promise((r) => setTimeout(r, 20))

    expect(received).toHaveLength(1)
    expect(received[0].type).toBe("session-expired")
    unsubscribe()
    pub.close()
    sub.close()
  })

  it("drops malformed / unrecognized messages instead of invoking subscribers", async () => {
    const raw = new BroadcastChannel("atol:test:malformed")
    const sub = createTokenBroadcast("atol:test:malformed")
    const handler = vi.fn()
    const unsubscribe = sub.subscribe(handler)

    raw.postMessage({ not: "a recognized shape" })
    raw.postMessage({ type: "not-our-type", accessToken: "x" })
    raw.postMessage(null)
    raw.postMessage("hello")
    raw.postMessage(42)
    await new Promise((r) => setTimeout(r, 20))

    expect(handler).not.toHaveBeenCalled()
    unsubscribe()
    sub.close()
    raw.close()
  })

  it("keeps the channel healthy when a subscriber throws", async () => {
    const pub = createTokenBroadcast("atol:test:throwing")
    const sub = createTokenBroadcast("atol:test:throwing")
    const good = vi.fn()
    const unsubBad = sub.subscribe(() => {
      throw new Error("subscriber boom")
    })
    const unsubGood = sub.subscribe(good)

    pub.publish({ type: "session-expired", sentAt: Date.now() })
    await new Promise((r) => setTimeout(r, 20))

    // A throwing subscriber must not prevent the other from receiving.
    expect(good).toHaveBeenCalledTimes(1)
    unsubBad()
    unsubGood()
    pub.close()
    sub.close()
  })

  it("stops delivering after unsubscribe", async () => {
    const pub = createTokenBroadcast("atol:test:unsub")
    const sub = createTokenBroadcast("atol:test:unsub")
    const handler = vi.fn()
    const unsubscribe = sub.subscribe(handler)
    unsubscribe()

    pub.publish({ type: "session-expired", sentAt: Date.now() })
    await new Promise((r) => setTimeout(r, 20))

    expect(handler).not.toHaveBeenCalled()
    pub.close()
    sub.close()
  })

  it("degrades to a no-op when BroadcastChannel is unavailable", async () => {
    const originalBC = (globalThis as unknown as { BroadcastChannel?: unknown })
      .BroadcastChannel
    Object.defineProperty(globalThis, "BroadcastChannel", {
      configurable: true,
      value: undefined,
    })
    try {
      expect(hasBroadcastSupport()).toBe(false)
      const bc = createTokenBroadcast("atol:test:noop")
      const handler = vi.fn()
      const unsubscribe = bc.subscribe(handler)
      bc.publish({ type: "session-expired", sentAt: 0 })
      await new Promise((r) => setTimeout(r, 5))
      expect(handler).not.toHaveBeenCalled()
      unsubscribe()
      bc.close()
    } finally {
      Object.defineProperty(globalThis, "BroadcastChannel", {
        configurable: true,
        value: originalBC,
      })
    }
  })
})
