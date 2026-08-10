/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import { ResponseVaultGrantRejectedError } from '../../src/oidc/response-vault'
import { NetworkError } from '../../src/oidc/token-recovery'
import {
  OPAQUE_A,
  OPAQUE_C,
  REQUEST_URI,
  activeReference,
  bootstrap,
  issuerBootstrap,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
  readAuthorizationSlots,
} from './response-vault-regression-helpers'
import { installResponseVaultLockManager } from './response-vault-lock-test-support'
import {
  mutateDatabase,
  pushedResponse,
  start,
} from './response-vault-expiry-test-support'

installResponseVaultRegressionHooks()

describe('response-vault server deadline custody', () => {
  it('retains bootstrap equality for terminal-only classification', async () => {
    const startedAt = Date.parse('2026-07-24T12:00:00.000Z')
    let now = startedAt
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    const captured = installFetchRouter((request) => {
      if (request.url.endsWith('/bootstrap')) {
        now = startedAt + 60_000
        return bootstrap(OPAQUE_A)
      }
      throw new Error(`unexpected request: ${request.url}`)
    })

    await expect(start(newVault())).rejects.toThrow(
      /invalid bootstrap response/,
    )

    expect(
      captured.filter((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      ),
    ).toHaveLength(0)
    expect(await readAuthorizationSlots()).toHaveLength(1)
    const reference = activeReference()
    expect(reference).toBeDefined()
    const record = await readAuthorizationRecord(reference!)
    expect(record).toMatchObject({ status: 'prepared' })
    expect(record?.executionOwner).toBeUndefined()
    expect(record?.executionExpiresAt).toBeUndefined()
  })

  it('persists an expired request URI before exact transaction rejection', async () => {
    let rejectionCount = 0
    const captured = installFetchRouter((request) => {
      if (request.url.endsWith('/pushed-authorization-requests')) {
        return pushedResponse(0, 600)
      }
      if (request.url.endsWith('/reject')) {
        rejectionCount++
        return noContent()
      }
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })

    await expect(start(newVault())).rejects.toMatchObject({
      code: 'invalid_request',
    })

    expect(rejectionCount).toBe(1)
    expect(
      captured.filter((request) => request.url.endsWith('/issuer-bootstrap')),
    ).toHaveLength(0)
    expect(await readAuthorizationSlots()).toEqual([])
    expectNoActiveReference()
  })

  it('rejects an expired pushed phase after reload without replaying PAR', async () => {
    let rejectionCount = 0
    const captured = installFetchRouter((request) => {
      if (request.url.endsWith('/reject')) {
        rejectionCount++
        return noContent()
      }
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = newVault()
    const authorization = await start(first)
    const now = Date.now()
    await mutateDatabase('authorizations', (transaction) => {
      const store = transaction.objectStore('authorizations')
      const request = store.get(authorization.reference.id)
      request.onsuccess = () => {
        store.put({
          ...(request.result as Record<string, unknown>),
          status: 'pushed',
          requestUri: REQUEST_URI,
          phaseExpiresAt: now,
          executionExpiresAt: now - 1,
        })
      }
    })
    installResponseVaultLockManager()

    await expect(start(newVault())).rejects.toMatchObject({
      code: 'invalid_request',
    })

    expect(rejectionCount).toBe(1)
    expect(
      captured.filter((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      ),
    ).toHaveLength(1)
    expectNoActiveReference()
  })

  it('uses request-start deadlines on replay and mirrors the transaction slot atomically', async () => {
    const startedAt = Date.parse('2026-07-24T12:00:00.000Z')
    let now = startedAt
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    let parAttempts = 0
    let resolveIssuerBootstrap: ((response: Response) => void) | undefined
    let markIssuerBootstrapStarted: (() => void) | undefined
    const issuerBootstrapStarted = new Promise<void>((resolve) => {
      markIssuerBootstrapStarted = resolve
    })
    installFetchRouter((request) => {
      if (request.url.endsWith('/pushed-authorization-requests')) {
        parAttempts++
        if (parAttempts <= 3) {
          throw new TypeError('ambiguous PAR transport')
        }
        return pushedResponse(40, 580)
      }
      if (request.url.endsWith('/issuer-bootstrap')) {
        markIssuerBootstrapStarted?.()
        return new Promise<Response>((resolve) => {
          resolveIssuerBootstrap = resolve
        })
      }
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ operationTimeoutMs: 1_000 })
    await expect(start(vault)).rejects.toBeInstanceOf(NetworkError)

    now = startedAt + 20_000
    const replay = start(vault)
    await issuerBootstrapStarted
    expect(resolveIssuerBootstrap).toBeDefined()

    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const record = await readAuthorizationRecord(reference)
    const slots = await readAuthorizationSlots()
    expect(record).toMatchObject({
      status: 'initializing',
      phaseExpiresAt: startedAt + 60_000,
      expiresAt: startedAt + 600_000,
    })
    expect(slots).toHaveLength(1)
    expect(slots[0]).toMatchObject({
      referenceId: reference,
      expiresAt: record.expiresAt,
    })

    resolveIssuerBootstrap!(issuerBootstrap(OPAQUE_C))
    await expect(replay).resolves.toMatchObject({ status: 'initialized' })
    expect(parAttempts).toBe(4)
  })

  it('bounds an iframe wait by the persisted transaction deadline', async () => {
    const startedAt = Date.parse('2026-07-24T12:00:00.000Z')
    let now = startedAt
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    installFetchRouter((request) => {
      if (request.url.endsWith('/pushed-authorization-requests')) {
        return pushedResponse(60, 600)
      }
      if (request.url.endsWith('/authorization-init')) {
        now = startedAt + 599_980
        return noContent()
      }
      if (request.url.endsWith('/reject')) return noContent()
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ iframeTimeoutMs: 5_000 })
    const elapsedStart = performance.now()

    await expect(vault.authorizeInIframe({})).rejects.toThrow(
      /iframe authorization timed out/,
    )
    expect(performance.now() - elapsedStart).toBeLessThan(500)
  })

  it('requires exact rejection at local equality before admitting a new grant', async () => {
    let rejectionCount = 0
    const captured = installFetchRouter((request) => {
      if (request.url.endsWith('/reject')) {
        rejectionCount++
        return noContent()
      }
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = await start(newVault())
    const firstRecord = await readAuthorizationRecord(first.reference.id)
    vi.spyOn(Date, 'now').mockReturnValue(firstRecord.expiresAt as number)
    installResponseVaultLockManager()
    await expect(start(newVault())).rejects.toBeInstanceOf(
      ResponseVaultGrantRejectedError,
    )
    const replacement = await start(newVault())

    expect(replacement.reference.id).not.toBe(first.reference.id)
    expect(await readAuthorizationRecord(first.reference.id)).toBeUndefined()
    expect(rejectionCount).toBe(1)
    expect(
      captured.filter((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      ),
    ).toHaveLength(2)
  })
})
