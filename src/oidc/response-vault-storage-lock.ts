import {
  RESPONSE_VAULT_EXECUTION_LOCK_WAIT_MS as EXECUTION_LOCK_WAIT_MS,
  ResponseVaultExecutionBusyError,
  type ResponseVaultExecutionClaim,
  type ResponseVaultReference,
} from './response-vault-model'

interface ResponseVaultLockManager {
  request<T>(
    name: string,
    options: {
      mode: 'exclusive'
      ifAvailable?: boolean
      signal?: AbortSignal
    },
    callback: (lock: Lock | null) => Promise<T>,
  ): Promise<T>
}

interface HeldResponseVaultExecutionLock {
  claimInProgress: boolean
  owner: string
  manager: ResponseVaultLockManager
  releaseHold: () => void
  request: Promise<void>
}

const heldResponseVaultExecutionLocks =
  new Map<string, HeldResponseVaultExecutionLock>()
const responseVaultCustodyRevisions = new WeakMap<object, number>()
const responseVaultExecutionErrors = new WeakMap<object, readonly unknown[]>()

function errorObject(value: unknown): object | undefined {
  if (
    (typeof value === 'object' && value !== null) ||
    typeof value === 'function'
  ) {
    return value
  }
  return undefined
}

function throwOrderedExecutionErrors(
  primary: unknown,
  cleanupErrors: readonly unknown[],
): never {
  const ordered = [primary, ...cleanupErrors]
  const object = errorObject(primary)
  if (object) {
    responseVaultExecutionErrors.set(object, ordered)
    throw primary
  }
  const error = new Error(
    'response vault: execution failed and lock cleanup also failed',
  )
  error.name = 'ResponseVaultExecutionCleanupError'
  responseVaultExecutionErrors.set(error, ordered)
  throw error
}

/**
 * Internal diagnostics for tests and trusted callers. The raw errors remain
 * outside the thrown Error object's inspectable properties so credential
 * custody cannot cross an error-reporting boundary accidentally.
 */
export function executionLockErrors(
  error: unknown,
): readonly unknown[] | undefined {
  const object = errorObject(error)
  return object ? responseVaultExecutionErrors.get(object) : undefined
}

function executionLockManager(): ResponseVaultLockManager {
  if (
    typeof navigator === 'undefined' ||
    !navigator.locks ||
    typeof navigator.locks.request !== 'function'
  ) {
    throw new Error('response vault: Web Locks is required')
  }
  return navigator.locks as ResponseVaultLockManager
}

export function rememberCustodyRevision<T extends object>(
  custody: T,
  revision: number,
): T {
  responseVaultCustodyRevisions.set(custody, revision)
  return custody
}

export function assertCustodyRevision(
  custody: object,
  revision: number,
): void {
  if (responseVaultCustodyRevisions.get(custody) !== revision) {
    throw new ResponseVaultExecutionBusyError()
  }
}

export function assertHeldExecutionLock(
  reference: ResponseVaultReference,
  claim: ResponseVaultExecutionClaim | undefined,
): asserts claim is ResponseVaultExecutionClaim {
  const held = heldResponseVaultExecutionLocks.get(reference.id)
  if (!claim || !held || held.owner !== claim.owner) {
    throw new ResponseVaultExecutionBusyError()
  }
}

export function responseVaultExecutionLockHeld(
  reference: ResponseVaultReference,
  claim: ResponseVaultExecutionClaim | undefined,
): boolean {
  const held = heldResponseVaultExecutionLocks.get(reference.id)
  return claim !== undefined && held?.owner === claim.owner
}

export async function acquireExecutionLock(
  reference: ResponseVaultReference,
  owner: string,
  waitForRelease: boolean,
): Promise<boolean> {
  const manager = executionLockManager()
  let existing = heldResponseVaultExecutionLocks.get(reference.id)
  if (existing && existing.manager !== manager) {
    heldResponseVaultExecutionLocks.delete(reference.id)
    existing.releaseHold()
    await existing.request.catch(() => undefined)
    existing = undefined
  }
  if (existing?.owner === owner) {
    if (existing.claimInProgress) {
      throw new ResponseVaultExecutionBusyError()
    }
    existing.claimInProgress = true
    return false
  }
  if (existing) {
    if (!waitForRelease) throw new ResponseVaultExecutionBusyError()
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([
        existing.request,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new ResponseVaultExecutionBusyError()),
            EXECUTION_LOCK_WAIT_MS,
          )
        }),
      ])
    } finally {
      if (timer !== undefined) clearTimeout(timer)
    }
    return acquireExecutionLock(reference, owner, waitForRelease)
  }
  let releaseHold!: () => void
  const hold = new Promise<void>((resolve) => {
    releaseHold = resolve
  })
  let resolveAcquired!: () => void
  let rejectAcquired!: (error: unknown) => void
  const acquired = new Promise<void>((resolve, reject) => {
    resolveAcquired = resolve
    rejectAcquired = reject
  })
  const abort = waitForRelease ? new AbortController() : undefined
  const timer = abort
    ? setTimeout(() => abort.abort(), EXECUTION_LOCK_WAIT_MS)
    : undefined
  let acquisitionSettled = false
  const held: HeldResponseVaultExecutionLock = {
    claimInProgress: true,
    owner,
    manager,
    releaseHold,
    request: Promise.resolve(),
  }
  const request = manager.request(
    `atol:response-vault:v1:${reference.id}`,
    {
      mode: 'exclusive',
      ifAvailable: waitForRelease ? undefined : true,
      signal: abort?.signal,
    },
    async (lock) => {
      if (!lock) {
        acquisitionSettled = true
        rejectAcquired(new ResponseVaultExecutionBusyError())
        return
      }
      if (heldResponseVaultExecutionLocks.has(reference.id)) {
        acquisitionSettled = true
        rejectAcquired(new ResponseVaultExecutionBusyError())
        return
      }
      heldResponseVaultExecutionLocks.set(reference.id, held)
      acquisitionSettled = true
      resolveAcquired()
      await hold
    },
  )
  held.request = request
  void request.catch((error) => {
    if (!acquisitionSettled) {
      if (
        error instanceof DOMException &&
        error.name === 'AbortError'
      ) {
        rejectAcquired(new ResponseVaultExecutionBusyError())
      } else {
        rejectAcquired(error)
      }
    }
  })
  try {
    await acquired
    return true
  } catch (error) {
    releaseHold()
    try {
      await request
    } catch {
      // Preserve the acquisition classification.
    }
    throw error
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

export function finishExecutionLockClaim(
  reference: ResponseVaultReference,
  owner: string,
): void {
  const held = heldResponseVaultExecutionLocks.get(reference.id)
  if (held?.owner === owner) {
    held.claimInProgress = false
  }
}

export async function releaseExecutionLock(
  reference: ResponseVaultReference,
  claim: ResponseVaultExecutionClaim | undefined,
): Promise<void> {
  assertHeldExecutionLock(reference, claim)
  await releaseOwnedExecutionLock(reference, claim.owner)
}

export async function releaseExecutionLockIfHeld(
  reference: ResponseVaultReference,
  claim: ResponseVaultExecutionClaim | undefined,
): Promise<void> {
  if (!claim) return
  await releaseOwnedExecutionLockIfHeld(reference, claim.owner)
}

export async function releaseOwnedExecutionLockIfHeld(
  reference: ResponseVaultReference,
  owner: string,
): Promise<void> {
  const held = heldResponseVaultExecutionLocks.get(reference.id)
  if (!held || held.owner !== owner) return
  await releaseOwnedExecutionLock(reference, owner)
}

export async function releaseOwnedExecutionLock(
  reference: ResponseVaultReference,
  owner: string,
): Promise<void> {
  const held = heldResponseVaultExecutionLocks.get(reference.id) as
    HeldResponseVaultExecutionLock | undefined
  if (!held || held.owner !== owner) {
    throw new ResponseVaultExecutionBusyError()
  }
  heldResponseVaultExecutionLocks.delete(reference.id)
  held.releaseHold()
  await held.request
}

export async function withExecutionLockRelease<T>(
  reference: ResponseVaultReference,
  claim: ResponseVaultExecutionClaim | undefined,
  operation: () => Promise<T>,
  close?: () => void,
): Promise<T> {
  let result: T | undefined
  let operationError: unknown
  let operationFailed = false
  const cleanupErrors: unknown[] = []
  try {
    try {
      result = await operation()
    } catch (error) {
      operationFailed = true
      operationError = error
    }
  } finally {
    if (close) {
      try {
        close()
      } catch (error) {
        cleanupErrors.push(error)
      }
    }
    try {
      await releaseExecutionLock(reference, claim)
    } catch (error) {
      cleanupErrors.push(error)
    }
  }

  if (operationFailed) {
    if (cleanupErrors.length > 0) {
      throwOrderedExecutionErrors(operationError, cleanupErrors)
    }
    throw operationError
  }
  if (cleanupErrors.length > 0) {
    const [primary, ...additional] = cleanupErrors
    if (additional.length > 0) {
      throwOrderedExecutionErrors(primary, additional)
    }
    throw primary
  }
  return result as T
}
