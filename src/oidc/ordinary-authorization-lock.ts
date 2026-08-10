import { bytesToBase64Url } from '../crypto/base64url'
import { OrdinaryAuthorizationPendingError } from './ordinary-authorization-model'

export interface HeldOrdinaryAuthorizationLock {
  release(): Promise<void>
}

export async function acquireOrdinaryAuthorizationCallbackLock(
  slotKey: string,
): Promise<HeldOrdinaryAuthorizationLock> {
  if (
    typeof navigator === 'undefined' ||
    !navigator.locks ||
    typeof navigator.locks.request !== 'function'
  ) {
    throw new Error(
      'ordinary browser authorization: Web Locks is required',
    )
  }
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(slotKey),
  )
  const name =
    `atol:ordinary-callback:${bytesToBase64Url(
      new Uint8Array(digest),
    )}`
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
  let acquisitionSettled = false
  const request = navigator.locks.request(
    name,
    { mode: 'exclusive', ifAvailable: true },
    async (lock) => {
      if (!lock) {
        acquisitionSettled = true
        rejectAcquired(new OrdinaryAuthorizationPendingError())
        return
      }
      acquisitionSettled = true
      resolveAcquired()
      await hold
    },
  )
  void request.catch((error) => {
    if (!acquisitionSettled) rejectAcquired(error)
  })
  try {
    await acquired
  } catch (error) {
    releaseHold()
    try {
      await request
    } catch (requestError) {
      throw requestError
    }
    throw error
  }
  let released = false
  return {
    release: async () => {
      if (released) return
      released = true
      releaseHold()
      await request
    },
  }
}
