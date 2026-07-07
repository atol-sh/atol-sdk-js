/**
 * Cross-tab mutual exclusion for renewal work.
 *
 * Uses the native Web Locks API (navigator.locks) for cross-tab mutual
 * exclusion. A leader tab acquires the lock and runs the critical
 * section; followers block until the leader releases, then re-enter the lock
 * themselves (at which point they typically find the state the leader
 * produced and short-circuit).
 *
 * In environments without `navigator.locks` (jsdom under vitest, old Safari,
 * workers with no locks API) we fall through to running `fn` directly. That
 * matches the existing intra-tab dedup semantics -- no regression, just no
 * cross-tab guarantee.
 */

interface LockManagerShape {
  request<T>(
    name: string,
    options: { mode?: "exclusive" | "shared"; ifAvailable?: boolean; steal?: boolean; signal?: AbortSignal },
    callback: (lock: unknown) => Promise<T>,
  ): Promise<T>
}

function getLockManager(): LockManagerShape | null {
  if (typeof navigator === "undefined") return null
  const mgr = (navigator as Navigator & { locks?: LockManagerShape }).locks
  return mgr && typeof mgr.request === "function" ? mgr : null
}

/**
 * Run `fn` under a cross-tab exclusive lock identified by `name`.
 *
 * The `ms` argument bounds the total wait time for acquiring the lock; if
 * the leader stalls beyond this, we abort and fall through to running `fn`
 * directly rather than deadlocking the caller. A 5s default -- leaders that
 * stall longer are almost certainly broken, and a
 * second POST to /auth/token is preferable to a forever-hung tab.
 *
 * The lock is per-origin (Web Locks is same-origin by construction), so the
 * lock name should include the authority + clientId to avoid cross-tenant
 * contention when multiple atol apps share an origin.
 */
export async function withTabLock<T>(
  name: string,
  ms: number,
  fn: () => Promise<T>,
): Promise<T> {
  const mgr = getLockManager()
  if (!mgr) return fn()

  const ac = new AbortController()
  const abort = setTimeout(() => ac.abort(), ms)
  try {
    return await mgr.request(name, { mode: "exclusive", signal: ac.signal }, async () => fn())
  } catch (err) {
    // AbortError after the timeout -- degrade to direct execution. Any
    // other error from inside fn propagates to the caller via this catch,
    // so re-throw non-timeout errors explicitly.
    if (err instanceof DOMException && err.name === "AbortError") {
      return fn()
    }
    throw err
  } finally {
    clearTimeout(abort)
  }
}

/** Whether the current environment supports cross-tab locks. Useful for tests. */
export function hasTabLockSupport(): boolean {
  return getLockManager() !== null
}
