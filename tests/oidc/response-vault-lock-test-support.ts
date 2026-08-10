import {
  acquireExecutionLock,
  releaseOwnedExecutionLock,
} from '../../src/oidc/response-vault-storage-lock'
import { ResponseVaultExecutionBusyError } from '../../src/oidc/response-vault-storage'

interface PendingLockRequest<T> {
  callback: (lock: Lock | null) => Promise<T> | T
  reject: (error: unknown) => void
  resolve: (value: T | PromiseLike<T>) => void
  signal?: AbortSignal
}

const responseVaultLockReleaseFailures =
  new WeakMap<LockManager, unknown[]>()

/**
 * Install a deterministic Web Locks implementation for jsdom. Replacing the
 * manager models a browser execution-context teardown between tests.
 */
export function installResponseVaultLockManager(): LockManager {
  const held = new Set<string>()
  const pending = new Map<string, Array<PendingLockRequest<unknown>>>()

  const run = <T>(
    name: string,
    request: PendingLockRequest<T>,
  ): void => {
    if (request.signal?.aborted) {
      request.reject(new DOMException('The operation was aborted', 'AbortError'))
      return
    }
    held.add(name)
    const release = () => {
      held.delete(name)
      const queue = pending.get(name)
      const next = queue?.shift()
      if (queue?.length === 0) pending.delete(name)
      if (next) run(name, next)
    }
    void Promise.resolve(
      request.callback({ name, mode: 'exclusive' } as Lock),
    ).then(
      (value) => {
        const failures = responseVaultLockReleaseFailures.get(locks)
        const failed = failures && failures.length > 0
        const failure = failed ? failures.shift() : undefined
        release()
        if (failed) request.reject(failure)
        else request.resolve(value)
      },
      (error) => {
        release()
        request.reject(error)
      },
    )
  }

  const locks = {
    request<T>(
      name: string,
      options: LockOptions,
      callback: (lock: Lock | null) => Promise<T> | T,
    ): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        if (options.ifAvailable && held.has(name)) {
          void Promise.resolve(callback(null)).then(resolve, reject)
          return
        }
        const request: PendingLockRequest<T> = {
          callback,
          reject,
          resolve,
          signal: options.signal,
        }
        if (!held.has(name)) {
          run(name, request)
          return
        }
        const queue = pending.get(name) ?? []
        queue.push(request as PendingLockRequest<unknown>)
        pending.set(name, queue)
        options.signal?.addEventListener(
          'abort',
          () => {
            const current = pending.get(name)
            const index = current?.indexOf(
              request as PendingLockRequest<unknown>,
            ) ?? -1
            if (index >= 0) current?.splice(index, 1)
            reject(new DOMException('The operation was aborted', 'AbortError'))
          },
          { once: true },
        )
      })
    },
  } as LockManager

  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: locks,
  })
  responseVaultLockReleaseFailures.set(locks, [])
  return locks
}

export function failNextResponseVaultLockRelease(
  manager: LockManager,
  error: unknown,
): void {
  const failures = responseVaultLockReleaseFailures.get(manager)
  if (!failures) {
    throw new Error('test Web Lock manager is unavailable')
  }
  failures.push(error)
}

export async function responseVaultLockIsReacquirable(
  manager: LockManager,
  referenceId: string,
): Promise<boolean> {
  if (navigator.locks !== manager) return false
  const reference = { version: 1, id: referenceId } as const
  const owner = 'L'.repeat(43)
  try {
    const acquired = await acquireExecutionLock(reference, owner, false)
    if (!acquired) return false
    await releaseOwnedExecutionLock(reference, owner)
    return navigator.locks === manager
  } catch (error) {
    if (error instanceof ResponseVaultExecutionBusyError) return false
    throw error
  }
}
