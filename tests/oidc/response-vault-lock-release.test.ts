/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import type { ResponseVault } from '../../src/oidc/response-vault'
import {
  beginResponseVaultNavigation,
  bindResponseVaultPAR,
  claimResponseVaultExecution,
  claimResponseVaultNavigation,
  claimResponseVaultRejection,
  claimResponseVaultTerminalProbe,
  discardResponseVaultAuthorization,
  discardResponseVaultCancellation,
  loadResponseVaultTerminalProbes,
  markResponseVaultInitialized,
  markResponseVaultInitializing,
  releaseResponseVaultCancellationExecution,
  releaseResponseVaultExecution,
  type ResponseVaultAuthorization,
  type ResponseVaultCancellation,
} from '../../src/oidc/response-vault-storage'
import {
  BINDING,
  activeAuthorization,
  claimedUnboundPARAuthorization,
  mutateDatabase,
  unboundPushedResponse,
} from './response-vault-adversarial-test-support'
import {
  activeReference,
  completeGrantPublication,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  protocolStartResponse,
  relaySuccess,
} from './response-vault-regression-helpers'
import { responseVaultLockIsReacquirable } from './response-vault-lock-test-support'

installResponseVaultRegressionHooks()

type RetryWaitInternals = {
  lifecycle: number
  ownedWaits: Set<(reason: Error) => void>
}

type RejectionInternals = {
  probePublishedTerminal(
    cancellation: ResponseVaultCancellation,
  ): Promise<void>
  rejectUnboundAuthorization(
    authorization: ResponseVaultAuthorization,
    pushed: ReturnType<typeof unboundPushedResponse>,
    error: unknown,
  ): Promise<never>
}

function currentLockManager(): LockManager {
  const manager = navigator.locks
  if (!manager) throw new Error('test Web Lock manager is unavailable')
  return manager
}

async function expectSameManagerReacquisition(
  manager: LockManager,
  referenceId: string,
): Promise<void> {
  await expect(
    responseVaultLockIsReacquirable(manager, referenceId),
  ).resolves.toBe(true)
}

async function expectIndexedDBFailure(
  operation: () => Promise<unknown>,
  expected: RegExp = /IndexedDB is unavailable/,
): Promise<void> {
  const browserIndexedDB = globalThis.indexedDB
  vi.stubGlobal('indexedDB', undefined)
  try {
    await expect(operation()).rejects.toThrow(expected)
  } finally {
    vi.stubGlobal('indexedDB', browserIndexedDB)
  }
}

async function advanceStoredRevision(referenceId: string): Promise<void> {
  await mutateDatabase('authorizations', (transaction) => {
    const store = transaction.objectStore('authorizations')
    const request = store.get(referenceId)
    request.onsuccess = () => {
      const record = request.result as Record<string, unknown>
      store.put({
        ...record,
        revision: Number(record.revision) + 1,
      })
    }
  })
}

function installSuccessfulProtocol(): void {
  installFetchRouter((request) => {
    const protocol = protocolStartResponse(request)
    if (protocol) return protocol
    if (request.url.endsWith('/relay')) return relaySuccess()
    if (request.url.endsWith('/acknowledge')) return noContent()
    if (request.url.endsWith('/reject')) return noContent()
    throw new Error(`unexpected request: ${request.url}`)
  })
}

async function claimedCancellation(
  vault: ResponseVault,
): Promise<ResponseVaultCancellation> {
  await vault.beginInteractive()
  const authorization = await activeAuthorization(vault)
  const owner = authorization.navigationOwner
  if (!owner) throw new Error('test navigation owner is unavailable')
  return claimResponseVaultRejection(
    authorization,
    owner,
    ['navigating'],
  )
}

async function initializedAuthorization(
  vault: ResponseVault,
): Promise<ResponseVaultAuthorization> {
  let authorization = await claimedUnboundPARAuthorization(vault)
  const pushed = unboundPushedResponse()
  authorization = await bindResponseVaultPAR(
    authorization,
    pushed.transactionId,
    pushed.requestUri,
    pushed.csrfToken,
    pushed.terminalProof,
    pushed.requestUriExpiresAt,
    pushed.transactionExpiresAt,
  )
  authorization = await markResponseVaultInitializing(authorization)
  return markResponseVaultInitialized(authorization)
}

async function publishedCancellation(
  vault: ResponseVault,
): Promise<ResponseVaultCancellation> {
  await vault.beginInteractive()
  const referenceId = activeReference()
  if (!referenceId) throw new Error('test authorization reference is missing')
  const grant = await vault.completeInteractive()
  await completeGrantPublication(grant)
  const batch = await loadResponseVaultTerminalProbes(
    BINDING,
    vault.lifecycleEpoch(),
  )
  const cancellation = batch.cancellations.find(
    ({ reference }) => reference.id === referenceId,
  )
  if (!cancellation) {
    throw new Error('test published cancellation is missing')
  }
  return cancellation
}

async function cancelRegisteredRetry(
  vault: ResponseVault,
  operation: Promise<unknown>,
): Promise<unknown> {
  const observed = operation.catch((error: unknown) => error)
  const internals = vault as unknown as RetryWaitInternals
  await vi.waitFor(() => expect(internals.ownedWaits.size).toBe(1))
  internals.lifecycle++
  const reason = new Error(
    'response vault: authorization lifecycle was superseded',
  )
  for (const cancel of internals.ownedWaits) cancel(reason)
  internals.ownedWaits.clear()
  return observed
}

describe('response-vault physical Web Lock release', () => {
  it('releases after navigation-begin IndexedDB failure', async () => {
    installSuccessfulProtocol()
    const authorization = await initializedAuthorization(newVault())
    const manager = currentLockManager()

    await expectIndexedDBFailure(() =>
      beginResponseVaultNavigation(
        authorization,
        authorization.expiresAt,
      ),
    )

    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases after authorization execution-release assertion failure', async () => {
    installSuccessfulProtocol()
    const authorization = await claimedUnboundPARAuthorization(newVault())
    const manager = currentLockManager()
    await advanceStoredRevision(authorization.reference.id)

    await expect(
      releaseResponseVaultExecution(authorization),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases after cancellation execution-release IndexedDB failure', async () => {
    installSuccessfulProtocol()
    const cancellation = await claimedCancellation(newVault())
    const manager = currentLockManager()

    await expectIndexedDBFailure(() =>
      releaseResponseVaultCancellationExecution(cancellation),
    )

    await expectSameManagerReacquisition(
      manager,
      cancellation.reference.id,
    )
  })

  it('releases after authorization-discard assertion failure', async () => {
    installSuccessfulProtocol()
    const authorization = await claimedUnboundPARAuthorization(newVault())
    const manager = currentLockManager()
    await advanceStoredRevision(authorization.reference.id)

    await expect(
      discardResponseVaultAuthorization(authorization),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases after cancellation-discard assertion failure', async () => {
    installSuccessfulProtocol()
    const cancellation = await claimedCancellation(newVault())
    const manager = currentLockManager()
    await advanceStoredRevision(cancellation.reference.id)

    await expect(
      discardResponseVaultCancellation(cancellation),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      cancellation.reference.id,
    )
  })

  it('releases after publication cleanup IndexedDB failure', async () => {
    installSuccessfulProtocol()
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) {
      throw new Error('test authorization reference is missing')
    }
    const grant = await vault.completeInteractive()
    await grant.acknowledge()
    await grant.finalize()
    const manager = currentLockManager()

    await expectIndexedDBFailure(
      () => grant.completePublication(),
      /local settlement cleanup remains pending/,
    )

    await expectSameManagerReacquisition(manager, referenceId)
  })

  it('releases a same-owner execution claim after a stale-revision assertion', async () => {
    installSuccessfulProtocol()
    const authorization = await claimedUnboundPARAuthorization(newVault())
    const owner = authorization.executionClaim?.owner
    if (!owner) throw new Error('test execution owner is unavailable')
    const manager = currentLockManager()
    await advanceStoredRevision(authorization.reference.id)

    await expect(
      claimResponseVaultExecution(
        authorization,
        owner,
        ['par_pending'],
      ),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases a same-owner navigation claim after a state assertion', async () => {
    installSuccessfulProtocol()
    const vault = newVault()
    await vault.beginInteractive()
    const navigating = await activeAuthorization(vault)
    const owner = navigating.navigationOwner
    if (!owner) throw new Error('test navigation owner is unavailable')
    const authorization = await claimResponseVaultNavigation(
      navigating,
      owner,
      'interactive',
    )
    const manager = currentLockManager()

    await expect(
      claimResponseVaultNavigation(
        authorization,
        owner,
        'interactive',
      ),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases a same-owner rejection claim after a stale-revision assertion', async () => {
    installSuccessfulProtocol()
    const cancellation = await claimedCancellation(newVault())
    const owner = cancellation.executionClaim?.owner
    if (!owner) throw new Error('test execution owner is unavailable')
    const manager = currentLockManager()
    await advanceStoredRevision(cancellation.reference.id)

    await expect(
      claimResponseVaultRejection(
        cancellation,
        owner,
        ['rejecting'],
      ),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      cancellation.reference.id,
    )
  })

  it('releases a same-owner terminal probe after a stale-revision assertion', async () => {
    installSuccessfulProtocol()
    const cancellation = await publishedCancellation(newVault())
    const owner = 'T'.repeat(43)
    const claimed = await claimResponseVaultTerminalProbe(
      cancellation,
      owner,
    )
    const manager = currentLockManager()
    await advanceStoredRevision(claimed.reference.id)

    await expect(
      claimResponseVaultTerminalProbe(claimed, owner),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      claimed.reference.id,
    )
  })

  it('releases an acknowledgement wait cancelled by lifecycle invalidation', async () => {
    let acknowledgementCalls = 0
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) {
        acknowledgementCalls++
        throw new TypeError('acknowledgement is unavailable')
      }
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) {
      throw new Error('test authorization reference is missing')
    }
    const grant = await vault.completeInteractive()
    const manager = currentLockManager()
    const acknowledgement = grant.acknowledge()
    void acknowledgement.catch(() => undefined)
    const internals = vault as unknown as RetryWaitInternals
    await vi.waitFor(() => expect(internals.ownedWaits.size).toBe(1))

    await expect(vault.invalidateLifecycle()).resolves.toBeUndefined()
    await expect(acknowledgement).rejects.toThrow(/lifecycle was superseded/)

    expect(acknowledgementCalls).toBe(1)
    await expectSameManagerReacquisition(manager, referenceId)
  })

  it('releases a finalization wait cancelled by the lifecycle', async () => {
    installFetchRouter((request) => {
      if (request.url.endsWith('/finalize')) {
        throw new TypeError('finalization is unavailable')
      }
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) {
      throw new Error('test authorization reference is missing')
    }
    const grant = await vault.completeInteractive()
    await grant.acknowledge()
    const manager = currentLockManager()

    const error = await cancelRegisteredRetry(vault, grant.finalize())

    expect(error).toBeInstanceOf(Error)
    await expectSameManagerReacquisition(manager, referenceId)
  })

  it('releases a rejection wait cancelled by the lifecycle', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/reject')) {
        throw new TypeError('rejection is unavailable')
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) {
      throw new Error('test authorization reference is missing')
    }
    const grant = await vault.completeInteractive()
    const manager = currentLockManager()

    const error = await cancelRegisteredRetry(vault, grant.reject())

    expect(error).toBeInstanceOf(Error)
    await expectSameManagerReacquisition(manager, referenceId)
  })

  it('releases a terminal-probe wait cancelled by the lifecycle', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      if (request.url.endsWith('/reject')) {
        throw new TypeError('terminal probe is unavailable')
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const cancellation = await publishedCancellation(vault)
    const manager = currentLockManager()
    const internals = vault as unknown as RejectionInternals

    const error = await cancelRegisteredRetry(
      vault,
      internals.probePublishedTerminal(cancellation),
    )

    expect(error).toBeInstanceOf(Error)
    await expectSameManagerReacquisition(
      manager,
      cancellation.reference.id,
    )
  })

  it('releases an unbound-rejection wait cancelled by the lifecycle', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) {
        throw new TypeError('unbound rejection is unavailable')
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const authorization = await claimedUnboundPARAuthorization(vault)
    const manager = currentLockManager()
    const internals = vault as unknown as RejectionInternals

    const error = await cancelRegisteredRetry(
      vault,
      internals.rejectUnboundAuthorization(
        authorization,
        unboundPushedResponse(),
        new Error('durable PAR binding failed'),
      ),
    )

    expect(error).toBeInstanceOf(Error)
    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })
})
