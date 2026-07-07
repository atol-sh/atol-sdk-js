import { afterEach, describe, expect, it, vi } from "vitest"
import { hasTabLockSupport, withTabLock } from "../../src/oidc/cross-tab-lock"

/**
 * The Web Locks API is not implemented in jsdom. Some tests install a
 * minimal mock; others rely on the fall-through path (which is what the
 * SDK uses in this environment at runtime too).
 */
function installMockLockManager(): {
  request: ReturnType<typeof vi.fn>
  restore: () => void
} {
  const request = vi.fn(
    async (_name: string, _opts: unknown, callback: (lock: unknown) => Promise<unknown>) => {
      return callback({})
    },
  )
  const original = (navigator as Navigator & { locks?: unknown }).locks
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: { request },
  })
  return {
    request,
    restore: () => {
      Object.defineProperty(navigator, "locks", {
        configurable: true,
        value: original,
      })
    },
  }
}

describe("withTabLock", () => {
  afterEach(() => {
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: undefined,
    })
  })

  it("falls through to running fn directly when navigator.locks is unavailable", async () => {
    expect(hasTabLockSupport()).toBe(false)
    expect(await withTabLock("x", 1_000, async () => 42)).toBe(42)
  })

  it("runs fn under the lock manager when one is present", async () => {
    const lock = installMockLockManager()
    try {
      const [ra, rb] = await Promise.all([
        withTabLock("gate", 1_000, async () => "a"),
        withTabLock("gate", 1_000, async () => "b"),
      ])
      expect(ra).toBe("a")
      expect(rb).toBe("b")
      expect(lock.request).toHaveBeenCalledTimes(2)
      expect(lock.request.mock.calls[0][0]).toBe("gate")
      expect(lock.request.mock.calls[1][0]).toBe("gate")
    } finally {
      lock.restore()
    }
  })

  it("propagates errors from the wrapped fn unchanged", async () => {
    const lock = installMockLockManager()
    try {
      await expect(
        withTabLock("gate", 1_000, async () => {
          throw new Error("inner-fail")
        }),
      ).rejects.toThrow("inner-fail")
    } finally {
      lock.restore()
    }
  })

  it("re-throws a non-abort error raised by the lock manager itself", async () => {
    const request = vi.fn(async () => {
      throw new Error("lock manager exploded")
    })
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: { request },
    })
    await expect(
      withTabLock("gate", 1_000, async () => "never"),
    ).rejects.toThrow(/lock manager exploded/)
  })

  it("reports no support and runs fn directly when navigator is undefined", async () => {
    const originalNavigator = globalThis.navigator
    // Remove navigator entirely (SSR / worker with no locks API).
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: undefined,
    })
    try {
      expect(hasTabLockSupport()).toBe(false)
      expect(await withTabLock("x", 1_000, async () => "direct")).toBe("direct")
    } finally {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: originalNavigator,
      })
    }
  })

  it("falls through to direct execution when navigator.locks aborts after the timeout", async () => {
    const request = vi.fn(
      async (
        _name: string,
        opts: { signal?: AbortSignal },
        _callback: (lock: unknown) => Promise<unknown>,
      ) => {
        return new Promise((_resolve, reject) => {
          opts.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"))
          })
        })
      },
    )
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: { request },
    })
    const start = Date.now()
    const result = await withTabLock("gate", 20, async () => "direct")
    expect(result).toBe("direct")
    expect(Date.now() - start).toBeLessThan(500)
  })
})
