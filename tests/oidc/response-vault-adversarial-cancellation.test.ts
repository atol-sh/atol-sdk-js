/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  loadActiveResponseVaultAuthorizationForRejection,
  type ResponseVaultAuthorization,
} from '../../src/oidc/response-vault-storage'
import {
  CLIENT_ORIGIN,
  OPAQUE_A,
  activeReference,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
} from './response-vault-regression-helpers'
import {
  BINDING,
  claimedUnboundPARAuthorization,
  mutateDatabase,
  unboundPushedResponse,
} from './response-vault-adversarial-test-support'

installResponseVaultRegressionHooks()

describe('response-vault adversarial recovery', () => {
  it('fails loud when IndexedDB authority is unavailable', async () => {
    const browserIndexedDB = globalThis.indexedDB
    vi.stubGlobal('indexedDB', undefined)
    try {
      await expect(
        loadActiveResponseVaultAuthorizationForRejection(BINDING, 0),
      ).rejects.toThrow(/IndexedDB is unavailable/)
    } finally {
      vi.stubGlobal('indexedDB', browserIndexedDB)
    }
  })

  it('uses exact cancellation authority when local PAR binding cannot be retained', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const authorization = await claimedUnboundPARAuthorization(vault)
    const originalError = new Error('durable PAR binding failed')
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
        originalError,
      ),
    ).rejects.toBe(originalError)

    const rejection = captured.find((request) =>
      request.url.endsWith('/reject'),
    )
    expect(rejection?.body).toMatchObject({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: authorization.tabSecret,
      cancellation_secret: authorization.cancellationSecret,
    })
    expectNoActiveReference()
    await expect(
      readAuthorizationRecord(authorization.reference.id),
    ).resolves.toBeUndefined()
  })

  it.each(['missing', 'malformed'] as const)(
    'rejects exact server authority with %s DPoP key custody before discovery',
    async (keyState) => {
      installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })
      const first = newVault()
      await first.beginInteractive()
      const reference = activeReference()
      if (!reference) {
        throw new Error('test authorization reference is missing')
      }
      const original = await readAuthorizationRecord(reference)

      await mutateDatabase('authorizations', (transaction) => {
        const store = transaction.objectStore('authorizations')
        const request = store.get(reference)
        request.onsuccess = () => {
          const record: Record<string, unknown> = {
            ...(request.result as Record<string, unknown>),
          }
          if (keyState === 'missing') {
            delete record.keys
          } else {
            record.keys = {
              privateKey: {},
              publicKey: {},
            }
          }
          store.put(record)
        }
      })

      let discoveryAttempts = 0
      let tokenAttempts = 0
      const rejectionBodies: Record<string, unknown>[] = []
      const durableAtRejection: Record<string, unknown>[] = []
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input)
          if (url === `${BINDING.issuer}/.well-known/openid-configuration`) {
            discoveryAttempts++
            throw new TypeError('discovery is unavailable')
          }
          if (url.endsWith('/auth/token')) {
            tokenAttempts++
            throw new Error('token exchange must not be attempted')
          }
          if (url === `${CLIENT_ORIGIN}/auth/browser/v1/reject`) {
            rejectionBodies.push(
              JSON.parse(String(init?.body)) as Record<string, unknown>,
            )
            durableAtRejection.push(await readAuthorizationRecord(reference))
            return noContent()
          }
          throw new Error(`unexpected recovery fetch ${url}`)
        }),
      )

      await expect(newVault().beginInteractive()).rejects.toThrow(
        /authorization binding mismatch/,
      )

      expect(discoveryAttempts).toBe(0)
      expect(tokenAttempts).toBe(0)
      expect(rejectionBodies).toEqual([
        {
          version: 1,
          mode: 'reject',
          transaction_id: original.transactionId,
          tab_secret: original.tabSecret,
          cancellation_secret: original.cancellationSecret,
        },
      ])
      expect(durableAtRejection).toHaveLength(1)
      expect(durableAtRejection[0]).toMatchObject({
        custody: 'cancellation',
        status: 'rejecting',
        transactionId: original.transactionId,
        tabSecret: original.tabSecret,
        cancellationSecret: original.cancellationSecret,
        expiresAt: original.expiresAt,
      })
      for (const field of [
        'keys',
        'jkt',
        'state',
        'nonce',
        'codeVerifier',
        'codeChallenge',
        'csrfToken',
        'parIdempotencyKey',
        'requestUri',
      ]) {
        expect(durableAtRejection[0]).not.toHaveProperty(field)
      }
      await expect(readAuthorizationRecord(reference)).resolves.toBeUndefined()
      expectNoActiveReference()
    },
  )
})
