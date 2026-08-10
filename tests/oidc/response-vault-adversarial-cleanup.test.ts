/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  ResponseVaultCleanupPendingError,
  ResponseVaultDeliveryUnavailableError,
  ResponseVaultGrantRejectedError,
  ResponseVaultRejectionBlockedError,
  ResponseVaultRejectionPendingError,
  ResponseVaultSettlementPendingError,
} from '../../src/oidc/response-vault'
import {
  aggregateCleanupError,
  takeResponseVaultDeliveryReturnTo,
  takeResponseVaultSettlementAuthorization,
} from '../../src/oidc/response-vault-contract'
import {
  loadResponseVaultCompensations,
  loadResponseVaultLifecycleCancellations,
  ResponseVaultAuthorizationBusyError,
  type ResponseVaultAuthorization,
} from '../../src/oidc/response-vault-storage'
import {
  CLIENT_ORIGIN,
  activeReference,
  discoveryDocument,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  jsonResponse,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
} from './response-vault-regression-helpers'
import {
  BINDING,
  activeAuthorization,
  cancellationRecord,
  canonicalRecordId,
  claimedUnboundPARAuthorization,
  mutateDatabase,
  unboundPushedResponse,
} from './response-vault-adversarial-test-support'

installResponseVaultRegressionHooks()

function errorObservables(error: Error): string {
  return [
    error.name,
    error.message,
    error.stack ?? '',
    JSON.stringify(error),
    ...Reflect.ownKeys(error).map(
      (key) => `${String(key)}=${String(Reflect.get(error, key))}`,
    ),
  ].join('\n')
}

describe('response-vault adversarial recovery', () => {
  it('advances a bounded cursor past unrelated compensation custody', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const source = await readAuthorizationRecord(reference)
    const exactId = canonicalRecordId(65)

    await mutateDatabase('authorizations', (transaction) => {
      const store = transaction.objectStore('authorizations')
      for (let index = 0; index < 65; index++) {
        store.put(
          cancellationRecord(source, canonicalRecordId(index), {
            clientId: `unrelated-${index}`,
          }),
        )
      }
      store.put(cancellationRecord(source, exactId))
    })

    const getAll = vi.spyOn(IDBObjectStore.prototype, 'getAll')
    const seen = new Set<string>()
    for (let pass = 0; pass < 3; pass++) {
      const batch = await loadResponseVaultCompensations(
        BINDING,
        vault.lifecycleEpoch(),
      )
      if (pass === 0) {
        const retry = await loadResponseVaultCompensations(
          BINDING,
          vault.lifecycleEpoch(),
        )
        expect(
          retry.cancellations.map((cancellation) => cancellation.reference.id),
        ).toEqual(
          batch.cancellations.map((cancellation) => cancellation.reference.id),
        )
        batch.commit()
        expect(() => retry.commit()).toThrow(/superseded/)
      } else {
        batch.commit()
      }
      expect(batch.cancellations.length).toBeLessThanOrEqual(64)
      expect(typeof batch.hasMore).toBe('boolean')
      for (const cancellation of batch.cancellations) {
        seen.add(cancellation.reference.id)
      }
    }
    expect(seen).toContain(exactId)
    expect(getAll).not.toHaveBeenCalled()
    getAll.mockRestore()
  })

  it('makes bounded progress across application-scoped cleanup batches', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const source = await readAuthorizationRecord(reference)

    await mutateDatabase('authorizations', (transaction) => {
      const store = transaction.objectStore('authorizations')
      for (let index = 0; index < 65; index++) {
        store.put(cancellationRecord(source, canonicalRecordId(index)))
      }
    })

    const seen = new Set<string>()
    for (let pass = 0; pass < 3; pass++) {
      const batch = await loadResponseVaultLifecycleCancellations(
        BINDING,
        vault.lifecycleEpoch(),
        'application',
      )
      expect(batch.cancellations.length).toBeLessThanOrEqual(64)
      expect(batch.errors).toEqual([])
      expect(typeof batch.hasMore).toBe('boolean')
      for (const cancellation of batch.cancellations) {
        seen.add(cancellation.reference.id)
      }
      batch.commit()
    }
    expect(seen).toHaveLength(65)
    expect(await readAuthorizationRecord(reference)).toMatchObject({
      id: reference,
      status: source.status,
    })
  })

  it('pins a malformed cancellation candidate without deleting live custody', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const source = await readAuthorizationRecord(reference)
    const malformedId = canonicalRecordId(0)
    await mutateDatabase('authorizations', (transaction) => {
      const malformed = cancellationRecord(source, malformedId)
      delete malformed.tabSecret
      transaction.objectStore('authorizations').put(malformed)
    })

    const first = await loadResponseVaultCompensations(
      BINDING,
      vault.lifecycleEpoch(),
    )
    const second = await loadResponseVaultCompensations(
      BINDING,
      vault.lifecycleEpoch(),
    )

    expect(first).toMatchObject({
      cancellations: [],
      hasMore: true,
      errors: [{ message: expect.stringMatching(/binding|custody/) }],
    })
    expect(second).toMatchObject({
      cancellations: [],
      hasMore: true,
      errors: [{ message: expect.stringMatching(/binding|custody/) }],
    })
    expect(await readAuthorizationRecord(reference)).toMatchObject({
      id: reference,
      status: source.status,
    })
  })

  it('surfaces a denied exact cancellation as a typed blocked error', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) {
        return jsonResponse({ error: 'invalid_request' }, 403)
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const authorization = await claimedUnboundPARAuthorization(vault)
    const internals = vault as unknown as {
      rejectUnboundAuthorization(
        current: ResponseVaultAuthorization,
        pushed: ReturnType<typeof unboundPushedResponse>,
        error: unknown,
      ): Promise<never>
    }

    await expect(
      internals.rejectUnboundAuthorization(
        authorization,
        unboundPushedResponse(),
        new Error('durable PAR binding failed'),
      ),
    ).rejects.toBeInstanceOf(ResponseVaultRejectionBlockedError)
  })

  it.each([
    [
      'malformed declared length',
      new Response(JSON.stringify(discoveryDocument()), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': 'not-a-number',
        },
      }),
      /response body exceeds the limit/,
    ],
    [
      'oversized declared length',
      new Response(JSON.stringify(discoveryDocument()), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(32 * 1024 + 1),
        },
      }),
      /response body exceeds the limit/,
    ],
    [
      'empty body',
      new Response(null, {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
      /response size is invalid/,
    ],
    [
      'non-success status',
      jsonResponse(discoveryDocument(), 503),
      /authorization server discovery failed/,
    ],
  ])('rejects a discovery response with %s', async (_name, response, error) => {
    installFetchRouter(
      (request) => {
        throw new Error(`unexpected request: ${request.url}`)
      },
      [response],
    )

    await expect(newVault().beginInteractive()).rejects.toThrow(error)
    expectNoActiveReference()
  })

  it('forgets causes on public settlement error types', () => {
    const sentinel = 'sentinel-secret-durable-cleanup'
    const cause = new Error(sentinel)
    const cleanup = new ResponseVaultCleanupPendingError(cause)
    const blocked = new ResponseVaultRejectionBlockedError(cause)
    const pending = new ResponseVaultRejectionPendingError(cause)
    const settlement = new ResponseVaultSettlementPendingError(cause)
    const rejected = new ResponseVaultGrantRejectedError()

    expect(cleanup.name).toBe('ResponseVaultCleanupPendingError')
    expect(blocked.name).toBe('ResponseVaultRejectionBlockedError')
    expect(pending.name).toBe('ResponseVaultRejectionPendingError')
    expect(settlement.name).toBe(
      'ResponseVaultSettlementPendingError',
    )
    expect(rejected).toMatchObject({
      name: 'ResponseVaultGrantRejectedError',
    })
    for (const error of [
      cleanup,
      blocked,
      pending,
      settlement,
    ]) {
      expect(error).not.toHaveProperty('cause')
      expect(JSON.stringify(error)).not.toContain(sentinel)
      expect(String(error)).not.toContain(sentinel)
      expect(error.stack).not.toContain(sentinel)
    }
  })

  it('keeps delivery routing behind a one-shot capability and out of diagnostics', () => {
    const sentinel = 'sentinel-secret-delivery-route'
    const returnTo = `/account?credential=${sentinel}#recovery`
    const error = new ResponseVaultDeliveryUnavailableError(returnTo)

    expect(error).toMatchObject({
      name: 'ResponseVaultDeliveryUnavailableError',
      code: 'response_vault_delivery_unavailable',
      message:
        'response vault: acknowledgement succeeded but the parsed delivery is no longer in memory',
    })
    expect(Reflect.ownKeys(error)).not.toContain('returnTo')
    expect(Reflect.get(error, 'returnTo')).toBeUndefined()
    expect(JSON.stringify(error)).not.toContain(sentinel)
    expect(String(error)).not.toContain(sentinel)
    expect(error.stack).not.toContain(sentinel)
    const inspected = Reflect.ownKeys(error)
      .map((key) => `${String(key)}=${String(Reflect.get(error, key))}`)
      .join('\n')
    expect(inspected).not.toContain(sentinel)

    const consoleSpy = vi
      .spyOn(console, 'error')
      .mockImplementation(() => {})
    console.error(error)
    expect(JSON.stringify(consoleSpy.mock.calls)).not.toContain(sentinel)
    consoleSpy.mockRestore()

    expect(takeResponseVaultDeliveryReturnTo(error)).toBe(returnTo)
    expect(takeResponseVaultDeliveryReturnTo(error)).toBeUndefined()
  })

  it('collapses cleanup failures without retaining raw errors or arrays', () => {
    const sentinel = 'sentinel-secret-cleanup-cause'
    const rawError = new Error(sentinel)
    const rawValue = {
      credential: sentinel,
      toString: () => sentinel,
    }

    for (const errors of [[rawError], [rawError, rawValue]]) {
      const aggregate = aggregateCleanupError(errors)
      expect(aggregate).toMatchObject({
        name: 'ResponseVaultCleanupPendingError',
        code: 'response_vault_cleanup_pending',
        message:
          'response vault: local settlement cleanup remains pending',
      })
      expect(aggregate).not.toHaveProperty('cause')
      expect(aggregate).not.toHaveProperty('errors')
      expect(Reflect.ownKeys(aggregate!)).not.toContain('errors')
      expect(JSON.stringify(aggregate)).not.toContain(sentinel)
      expect(String(aggregate)).not.toContain(sentinel)
      expect(aggregate?.stack).not.toContain(sentinel)
      const inspected = Reflect.ownKeys(aggregate!)
        .map((key) => `${String(key)}=${String(Reflect.get(aggregate!, key))}`)
        .join('\n')
      expect(inspected).not.toContain(sentinel)
    }
    expect(aggregateCleanupError([])).toBeUndefined()
  })

  it('collapses a raw grant-restoration failure at the custody boundary', async () => {
    const sentinel = 'sentinel-secret-grant-restoration'
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    await newVault().beginInteractive()
    vi.spyOn(crypto.subtle, 'exportKey').mockRejectedValue(
      new Error(sentinel),
    )

    const error = await newVault()
      .beginInteractive()
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({
      name: 'ResponseVaultCleanupPendingError',
      code: 'response_vault_cleanup_pending',
      message:
        'response vault: local settlement cleanup remains pending',
    })
    expect(error).not.toHaveProperty('cause')
    expect(error).not.toHaveProperty('errors')
    expect(JSON.stringify(error)).not.toContain(sentinel)
    expect(String(error)).not.toContain(sentinel)
    if (!(error instanceof Error)) {
      throw new Error('expected a closed custody Error')
    }
    expect(error.stack).not.toContain(sentinel)
    expect(
      Reflect.ownKeys(error)
        .map((key) => `${String(key)}=${String(Reflect.get(error, key))}`)
        .join('\n'),
    ).not.toContain(sentinel)
    console.error(error)
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain(
      sentinel,
    )
  })

  it('reconstructs a recognized custody error without attacker decorations', async () => {
    const sentinel = 'sentinel-secret-decorated-custody-error'
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    await newVault().beginInteractive()
    const decorated = Object.assign(
      new ResponseVaultAuthorizationBusyError(),
      {
        cause: new Error(sentinel),
        url: `https://app.example.com/callback?credential=${sentinel}`,
        caught: { credential: sentinel },
      },
    )
    vi.spyOn(crypto.subtle, 'exportKey').mockRejectedValue(decorated)

    const error = await newVault()
      .beginInteractive()
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ResponseVaultAuthorizationBusyError)
    expect(error).not.toBe(decorated)
    if (!(error instanceof Error)) {
      throw new Error('expected a closed custody Error')
    }
    expect(error).not.toHaveProperty('cause')
    expect(error).not.toHaveProperty('url')
    expect(error).not.toHaveProperty('caught')
    expect(errorObservables(error)).not.toContain(sentinel)
  })

  it('classifies a hostile caught proxy without inspecting or retaining it', async () => {
    const sentinel = 'sentinel-secret-hostile-custody-proxy'
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    await newVault().beginInteractive()
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error(sentinel)
        },
      },
    )
    vi.spyOn(crypto.subtle, 'exportKey').mockRejectedValue(hostile)

    const error = await newVault()
      .beginInteractive()
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ResponseVaultCleanupPendingError)
    if (!(error instanceof Error)) {
      throw new Error('expected a closed custody Error')
    }
    expect(error).not.toHaveProperty('cause')
    expect(errorObservables(error)).not.toContain(sentinel)
  })

  it('keeps abandoned cleanup authoritative when rejection transport also fails', async () => {
    const sentinel = 'sentinel-secret-colliding-custody-failures'
    let rejectionAttempts = 0
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) {
        rejectionAttempts++
        throw new TypeError(sentinel)
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    await newVault().beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const source = await readAuthorizationRecord(reference)
    await mutateDatabase('authorizations', (transaction) => {
      const store = transaction.objectStore('authorizations')
      const malformed = cancellationRecord(
        source,
        canonicalRecordId(0),
      )
      delete malformed.tabSecret
      store.put(malformed)
      store.put({
        ...source,
        keys: { privateKey: {}, publicKey: {} },
      })
    })

    const error = await newVault()
      .beginInteractive()
      .catch((caught: unknown) => caught)

    expect(rejectionAttempts).toBeGreaterThan(0)
    expect(error).toMatchObject({
      name: 'ResponseVaultCleanupPendingError',
      code: 'response_vault_cleanup_pending',
      message:
        'response vault: local settlement cleanup remains pending',
    })
    if (!(error instanceof Error)) {
      throw new Error('expected a closed custody Error')
    }
    expect(error).not.toHaveProperty('cause')
    expect(errorObservables(error)).not.toContain(sentinel)
  })

  it('keeps exact settlement custody behind a one-shot internal capability', async () => {
    const sentinel = 'sentinel-secret-settlement-authority'
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive({
      returnTo: `/account?credential=${sentinel}`,
    })
    const authorization = await activeAuthorization(vault)
    authorization.codeVerifier = sentinel
    const error = new ResponseVaultSettlementPendingError(
      new Error(sentinel),
      authorization,
    )

    expect(error).toMatchObject({
      name: 'ResponseVaultSettlementPendingError',
      code: 'response_vault_settlement_pending',
      message:
        'response vault: settlement remains pending and can be retried',
    })
    expect(Reflect.ownKeys(error)).not.toContain('authorization')
    expect(Reflect.ownKeys(error)).not.toContain('cause')
    expect(Reflect.get(error, 'authorization')).toBeUndefined()
    const inspected = Reflect.ownKeys(error)
      .map((key) => `${String(key)}=${String(Reflect.get(error, key))}`)
      .join('\n')
    expect(inspected).not.toContain(sentinel)
    expect(JSON.stringify(error)).not.toContain(sentinel)
    expect(String(error)).not.toContain(sentinel)

    const consoleSpy = vi
      .spyOn(console, 'error')
      .mockImplementation(() => {})
    console.error(error)
    expect(JSON.stringify(consoleSpy.mock.calls)).not.toContain(sentinel)
    consoleSpy.mockRestore()

    expect(
      takeResponseVaultSettlementAuthorization(error),
    ).toBe(authorization)
    expect(
      takeResponseVaultSettlementAuthorization(error),
    ).toBeUndefined()
  })

  it('rejects invalid operation deadlines and cross-origin return targets', async () => {
    expect(() => newVault({ operationTimeoutMs: 0 })).toThrow(
      /operation timeout is invalid/,
    )
    expect(() => newVault({ operationTimeoutMs: 60_001 })).toThrow(
      /operation timeout is invalid/,
    )

    await expect(
      newVault().beginInteractive({
        returnTo: `${CLIENT_ORIGIN.replace('app', 'attacker')}/account`,
      }),
    ).rejects.toThrow(/authorization intent is invalid/)
    expectNoActiveReference()
  })
})
