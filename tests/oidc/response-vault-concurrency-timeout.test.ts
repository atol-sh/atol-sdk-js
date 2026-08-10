/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  ResponseVaultSettlementPendingError,
} from '../../src/oidc/response-vault'
import {
  ResponseVaultAuthorizationBusyError,
} from '../../src/oidc/response-vault-storage'
import { NetworkError } from '../../src/oidc/token-recovery'
import {
  activeReference,
  completeGrantPublication,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  OPAQUE_A,
  protocolStartResponse,
  readAuthorizationRecord,
  rejectWhenAborted,
  relaySuccess,
} from './response-vault-regression-helpers'

installResponseVaultRegressionHooks()

describe('response-vault concurrency and operation deadlines', () => {
  it('uses durable CAS to admit one interleaved start and preserve its custody', async () => {
    const captured = installFetchRouter((request) => {
      const startResponse = protocolStartResponse(request)
      if (startResponse) return startResponse
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = newVault()
    const second = newVault()
    type StartInternals = {
      activeAuthorization(epoch: number): Promise<unknown>
    }
    const firstInternals = first as unknown as StartInternals
    const secondInternals = second as unknown as StartInternals
    const firstRead = firstInternals.activeAuthorization.bind(first)
    const secondRead = secondInternals.activeAuthorization.bind(second)
    let arrivals = 0
    let release: (() => void) | undefined
    const interleave = new Promise<void>((resolve) => {
      release = resolve
    })
    const waitAfterRead = async (
      read: (epoch: number) => Promise<unknown>,
      epoch: number,
    ): Promise<unknown> => {
      const result = await read(epoch)
      arrivals++
      if (arrivals === 2) release?.()
      await interleave
      return result
    }
    vi.spyOn(firstInternals, 'activeAuthorization').mockImplementation(
      (epoch) => waitAfterRead(firstRead, epoch),
    )
    vi.spyOn(secondInternals, 'activeAuthorization').mockImplementation(
      (epoch) => waitAfterRead(secondRead, epoch),
    )

    const outcomes = await Promise.allSettled([
      first.beginInteractive(),
      second.beginInteractive(),
    ])

    expect(outcomes.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    const rejected = outcomes.find(({ status }) => status === 'rejected')
    expect(rejected).toBeDefined()
    if (rejected?.status === 'rejected') {
      expect(rejected.reason).toBeInstanceOf(
        ResponseVaultAuthorizationBusyError,
      )
    }
    expect(
      captured.filter((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      ),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/bootstrap')),
    ).toHaveLength(2)

    const reference = activeReference()
    expect(reference).toBeDefined()
    await expect(readAuthorizationRecord(reference!)).resolves.toMatchObject({
      status: 'navigating',
      transactionId: OPAQUE_A,
    })

    const recovered = await newVault().completeInteractive()
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expect(
      captured.find((request) => request.url.endsWith('/relay'))?.body
        .transaction_id,
    ).toBe(OPAQUE_A)
    await completeGrantPublication(recovered)
    expectNoActiveReference()
  })

  it('bounds a never-resolving bootstrap request', async () => {
    let aborts = 0
    installFetchRouter((request) => {
      if (request.url.endsWith('/bootstrap')) {
        return rejectWhenAborted(request, () => {
          aborts++
        })
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ operationTimeoutMs: 25 })
    const startedAt = Date.now()

    await expect(vault.beginInteractive()).rejects.toBeInstanceOf(NetworkError)

    expect(Date.now() - startedAt).toBeLessThan(1_000)
    expect(aborts).toBe(1)
    const reference = activeReference()
    expect(reference).toBeDefined()
    const record = await readAuthorizationRecord(reference!)
    expect(record).toMatchObject({ status: 'prepared' })
    expect(record?.executionOwner).toBeUndefined()
    expect(record?.executionExpiresAt).toBeUndefined()
  })

  it('cancels an oversized streaming response before buffering the full body', async () => {
    let canceled = false
    installFetchRouter((request) => {
      if (!request.url.endsWith('/bootstrap')) {
        throw new Error(`unexpected request: ${request.url}`)
      }
      const chunk = new Uint8Array(20 * 1024)
      chunk.fill(65)
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(chunk)
          controller.enqueue(chunk)
        },
        cancel() {
          canceled = true
        },
      })
      return new Response(stream, {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    await expect(newVault().beginInteractive()).rejects.toThrow(
      /response body exceeds the limit/,
    )

    expect(canceled).toBe(true)
    const reference = activeReference()
    expect(reference).toBeDefined()
    const record = await readAuthorizationRecord(reference!)
    expect(record).toMatchObject({ status: 'prepared' })
    expect(record?.executionOwner).toBeUndefined()
    expect(record?.executionExpiresAt).toBeUndefined()
  })

  it('bounds relay transport and leaves the exact transaction retryable', async () => {
    let relayCalls = 0
    let aborts = 0
    const captured = installFetchRouter((request) => {
      const startResponse = protocolStartResponse(request)
      if (startResponse) return startResponse
      if (request.url.endsWith('/relay')) {
        relayCalls++
        if (relayCalls === 1) {
          return rejectWhenAborted(request, () => {
            aborts++
          })
        }
        return relaySuccess()
      }
      if (request.url.endsWith('/acknowledge')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ operationTimeoutMs: 25 })
    await vault.beginInteractive()
    const startedAt = Date.now()

    await expect(vault.completeInteractive()).rejects.toBeInstanceOf(
      NetworkError,
    )

    expect(Date.now() - startedAt).toBeLessThan(1_000)
    expect(aborts).toBe(1)
    const reference = activeReference()
    expect(reference).toBeDefined()
    await expect(readAuthorizationRecord(reference!)).resolves.toMatchObject({
      status: 'relay_retry',
      transactionId: OPAQUE_A,
    })

    const grant = await vault.completeInteractive()
    const relayRequests = captured.filter((request) =>
      request.url.endsWith('/relay'),
    )
    expect(relayRequests).toHaveLength(2)
    expect(relayRequests.map(({ body }) => body.transaction_id)).toEqual([
      OPAQUE_A,
      OPAQUE_A,
    ])
    await completeGrantPublication(grant)
    expectNoActiveReference()
  })

  it('bounds acknowledgement transport and preserves durable settlement', async () => {
    let acknowledgementCalls = 0
    let aborts = 0
    const captured = installFetchRouter((request) => {
      const startResponse = protocolStartResponse(request)
      if (startResponse) return startResponse
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) {
        acknowledgementCalls++
        if (acknowledgementCalls <= 3) {
          return rejectWhenAborted(request, () => {
            aborts++
          })
        }
        return noContent()
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ operationTimeoutMs: 25 })
    await vault.beginInteractive()
    const grant = await vault.completeInteractive()
    const startedAt = Date.now()

    await expect(grant.acknowledge()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )

    expect(Date.now() - startedAt).toBeLessThan(2_000)
    expect(aborts).toBe(3)
    const reference = activeReference()
    expect(reference).toBeDefined()
    await expect(readAuthorizationRecord(reference!)).resolves.toMatchObject({
      status: 'awaiting_ack',
      settlementKind: 'success',
      transactionId: OPAQUE_A,
    })

    const retained = await vault.completeInteractive()
    expect(retained).toBe(grant)
    await retained.acknowledge()
    await retained.finalize()
    await retained.completePublication()
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expect(acknowledgementCalls).toBe(4)
    expectNoActiveReference()
  })

  it('aborts an outstanding owned request when the lifecycle is invalidated', async () => {
    let aborts = 0
    const captured = installFetchRouter((request) => {
      if (request.url.endsWith('/bootstrap')) {
        return rejectWhenAborted(request, () => {
          aborts++
        })
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ operationTimeoutMs: 5_000 })
    const pending = vault.beginInteractive()
    void pending.catch(() => undefined)
    await vi.waitFor(() => expect(captured).toHaveLength(1))
    const invalidatedAt = Date.now()

    await vault.invalidateLifecycle()
    await expect(pending).rejects.toBeInstanceOf(NetworkError)

    expect(Date.now() - invalidatedAt).toBeLessThan(500)
    expect(aborts).toBe(1)
    expect(captured[0].init.signal?.aborted).toBe(true)
    expectNoActiveReference()
  })
})
