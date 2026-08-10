/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  ResponseVaultCleanupPendingError,
  ResponseVaultRejectionPendingError,
  type ResponseVault,
  type ResponseVaultGrant,
} from '../../src/oidc/response-vault'
import {
  rotateLogoutGeneration,
  type CredentialGenerationSnapshot,
} from '../../src/oidc/credential-generation'
import {
  bindResponseVaultPAR,
  claimResponseVaultExecution,
  loadResponseVaultTerminalProbes,
  markResponseVaultInitialized,
  markResponseVaultInitializing,
  releaseResponseVaultExecution,
  type ResponseVaultAuthorization,
  type ResponseVaultIntent,
} from '../../src/oidc/response-vault-storage'
import {
  executionLockErrors,
} from '../../src/oidc/response-vault-storage-lock'
import {
  BINDING,
  claimedUnboundPARAuthorization,
  mutateDatabase,
  unboundPushedResponse,
} from './response-vault-adversarial-test-support'
import {
  activeReference,
  completeGrantPublication,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  jsonResponse,
  newVault,
  noContent,
  protocolStartResponse,
  relaySuccess,
} from './response-vault-regression-helpers'
import {
  failNextResponseVaultLockRelease,
  responseVaultLockIsReacquirable,
} from './response-vault-lock-test-support'

installResponseVaultRegressionHooks()

type RelayInternals = {
  relay(
    authorization: ResponseVaultAuthorization,
  ): Promise<ResponseVaultGrant>
}

type RejectionInternals = {
  probePublishedTerminal(
    cancellation: Awaited<ReturnType<typeof publishedCancellation>>,
  ): Promise<void>
}

type StartInternals = {
  start(
    mode: 'interactive',
    intent: ResponseVaultIntent,
    expectedGeneration?: CredentialGenerationSnapshot,
  ): Promise<ResponseVaultAuthorization>
}

type EndpointInternals = {
  endpointsAuthority: unknown
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

async function publishedCancellation(vault: ResponseVault) {
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

async function capturedError(
  operation: () => Promise<unknown>,
): Promise<unknown> {
  try {
    await operation()
  } catch (error) {
    return error
  }
  throw new Error('test operation unexpectedly succeeded')
}

describe('response-vault Web Lock release regressions', () => {
  it('does not let a concurrent same-owner loser release live custody', async () => {
    installSuccessfulProtocol()
    const authorization = await claimedUnboundPARAuthorization(newVault())
    const owner = authorization.executionClaim?.owner
    if (!owner) throw new Error('test execution owner is unavailable')
    const manager = currentLockManager()

    const claims = await Promise.allSettled([
      claimResponseVaultExecution(authorization, owner, ['par_pending']),
      claimResponseVaultExecution(authorization, owner, ['par_pending']),
    ])
    const fulfilled = claims.filter(
      (
        result,
      ): result is PromiseFulfilledResult<ResponseVaultAuthorization> =>
        result.status === 'fulfilled',
    )
    const rejected = claims.filter(
      (result): result is PromiseRejectedResult =>
        result.status === 'rejected',
    )

    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    await expect(
      responseVaultLockIsReacquirable(
        manager,
        authorization.reference.id,
      ),
    ).resolves.toBe(false)

    await releaseResponseVaultExecution(fulfilled[0].value)
    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('keeps the operation error primary when physical release also fails', async () => {
    installSuccessfulProtocol()
    const authorization = await claimedUnboundPARAuthorization(newVault())
    const manager = currentLockManager()
    const releaseError = new Error('injected Web Lock release failure')
    await advanceStoredRevision(authorization.reference.id)
    failNextResponseVaultLockRelease(manager, releaseError)

    const error = await capturedError(() =>
      releaseResponseVaultExecution(authorization),
    )

    expect(error).not.toBe(releaseError)
    expect(executionLockErrors(error)).toEqual([error, releaseError])
    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('reports a physical release failure after a successful transition', async () => {
    installSuccessfulProtocol()
    const authorization = await claimedUnboundPARAuthorization(newVault())
    const manager = currentLockManager()
    const releaseError = new Error('injected Web Lock release failure')
    failNextResponseVaultLockRelease(manager, releaseError)

    const error = await capturedError(() =>
      releaseResponseVaultExecution(authorization),
    )

    expect(error).toBe(releaseError)
    expect(executionLockErrors(error)).toBeUndefined()
    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('still releases the physical lock when database close throws', async () => {
    installSuccessfulProtocol()
    const authorization = await claimedUnboundPARAuthorization(newVault())
    const manager = currentLockManager()
    const closeError = new Error('injected database close failure')
    await advanceStoredRevision(authorization.reference.id)
    const originalClose = IDBDatabase.prototype.close
    const close = vi
      .spyOn(IDBDatabase.prototype, 'close')
      .mockImplementationOnce(function (this: IDBDatabase) {
        originalClose.call(this)
        throw closeError
      })

    const error = await capturedError(() =>
      releaseResponseVaultExecution(authorization),
    )
    close.mockRestore()

    expect(error).not.toBe(closeError)
    expect(executionLockErrors(error)).toEqual([error, closeError])
    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases when relay hits a stale-custody assertion', async () => {
    installSuccessfulProtocol()
    const vault = newVault()
    const authorization = await initializedAuthorization(vault)
    const manager = currentLockManager()
    await advanceStoredRevision(authorization.reference.id)

    await expect(
      (vault as unknown as RelayInternals).relay(authorization),
    ).rejects.toThrow()

    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases when post-start generation validation fails', async () => {
    installSuccessfulProtocol()
    const vault = newVault()
    const manager = currentLockManager()
    const internals = vault as unknown as StartInternals
    const start = internals.start.bind(vault)
    let authorization: ResponseVaultAuthorization | undefined
    internals.start = async (...args) => {
      authorization = await start(...args)
      rotateLogoutGeneration(BINDING)
      return authorization
    }

    await expect(vault.beginInteractive()).rejects.toThrow()

    if (!authorization) {
      throw new Error('test authorization custody is unavailable')
    }
    await expectSameManagerReacquisition(
      manager,
      authorization.reference.id,
    )
  })

  it('releases when acknowledgement endpoint discovery fails', async () => {
    installSuccessfulProtocol()
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) throw new Error('test authorization reference is missing')
    const grant = await vault.completeInteractive()
    const manager = currentLockManager()
    ;(vault as unknown as EndpointInternals).endpointsAuthority = undefined
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('discovery is unavailable')
      }),
    )

    await expect(grant.acknowledge()).rejects.toThrow()

    await expectSameManagerReacquisition(manager, referenceId)
  })

  it('does not retry a terminal probe after local cleanup fails', async () => {
    let terminalProbeCalls = 0
    const browserIndexedDB = globalThis.indexedDB
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      if (request.url.endsWith('/reject')) {
        terminalProbeCalls++
        vi.stubGlobal('indexedDB', undefined)
        return jsonResponse({ error: 'authorization_terminal' }, 410)
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const cancellation = await publishedCancellation(vault)
    const manager = currentLockManager()

    try {
      await expect(
        (vault as unknown as RejectionInternals).probePublishedTerminal(
          cancellation,
        ),
      ).rejects.toBeInstanceOf(ResponseVaultCleanupPendingError)
    } finally {
      vi.stubGlobal('indexedDB', browserIndexedDB)
    }

    expect(terminalProbeCalls).toBe(1)
    await expectSameManagerReacquisition(
      manager,
      cancellation.reference.id,
    )
  })

  it('retries ambiguous rejection through the same grant instance', async () => {
    let rejectionAttempts = 0
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/reject')) {
        rejectionAttempts++
        if (rejectionAttempts <= 3) {
          throw new TypeError('lost rejection response')
        }
        return noContent()
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) throw new Error('test authorization reference is missing')
    const grant = await vault.completeInteractive()
    const manager = currentLockManager()

    await expect(grant.reject()).rejects.toBeInstanceOf(
      ResponseVaultRejectionPendingError,
    )
    await expect(grant.reject()).resolves.toBeUndefined()

    expect(rejectionAttempts).toBe(4)
    expectNoActiveReference()
    await expectSameManagerReacquisition(manager, referenceId)
  })
})
