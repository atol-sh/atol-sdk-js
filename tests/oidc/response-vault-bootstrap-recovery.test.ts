/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it } from 'vitest'
import { ResponseVaultAuthorizationBusyError } from '../../src/oidc/response-vault-storage'
import {
  OPAQUE_A,
  activeReference,
  bootstrap,
  bootstrapAttemptChallenge,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  jsonResponse,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
  readAuthorizationSlots,
  type CapturedRequest,
} from './response-vault-regression-helpers'
import { start } from './response-vault-expiry-test-support'

installResponseVaultRegressionHooks()

function bootstrapRequests(
  captured: CapturedRequest[],
): CapturedRequest[] {
  return captured.filter((request) => request.url.endsWith('/bootstrap'))
}

function exactBootstrapCapabilities(
  request: CapturedRequest,
): Record<string, unknown> {
  return {
    tabSecret: request.body.tab_secret,
    cancellationSecret: request.body.cancellation_secret,
    parIdempotencyKey: request.body.par_idempotency_key,
  }
}

function expectReleasedPreparedRecord(
  record: Record<string, unknown>,
  request: CapturedRequest,
): void {
  expect(record).toMatchObject({
    status: 'prepared',
    ...exactBootstrapCapabilities(request),
  })
  expect(record).not.toHaveProperty('executionOwner')
  expect(record).not.toHaveProperty('executionExpiresAt')
}

describe('response-vault bootstrap recovery', () => {
  it.each([
    ['browser cookie applied before the response was lost', 'lost'],
    ['browser cookie lost while the server was unavailable', 'unavailable'],
  ] as const)(
    'recovers exact prepared custody when the %s',
    async (_label, firstOutcome) => {
      let bootstrapAttempt = 0
      let serverCookie: 'absent' | 'applied' = 'absent'
      const captured = installFetchRouter((request) => {
        if (request.url.endsWith('/bootstrap')) {
          if (!request.body.attempt_capability) {
            return bootstrapAttemptChallenge()
          }
          bootstrapAttempt++
          if (bootstrapAttempt === 1) {
            if (firstOutcome === 'lost') {
              serverCookie = 'applied'
              throw new TypeError('bootstrap response was lost')
            }
            return jsonResponse({ error: 'unavailable' }, 503)
          }
          expect(serverCookie).toBe(
            firstOutcome === 'lost' ? 'applied' : 'absent',
          )
          serverCookie = 'applied'
          return bootstrap(OPAQUE_A)
        }
        if (request.url.endsWith('/reject')) return noContent()
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })

      const firstVault = newVault()
      await expect(firstVault.beginInteractive()).rejects.toThrow()

      const reference = activeReference()
      expect(reference).toBeDefined()
      const mintBootstrap = bootstrapRequests(captured)[0]
      const firstBootstrap = bootstrapRequests(captured)[1]
      expect(mintBootstrap.body).not.toHaveProperty(
        'attempt_capability',
      )
      expect(firstBootstrap.body).toEqual({
        version: 1,
        mode: 'create',
        tab_secret: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
        cancellation_secret: expect.stringMatching(
          /^[A-Za-z0-9_-]{43}$/,
        ),
        par_idempotency_key: expect.stringMatching(
          /^[A-Za-z0-9_-]{43}$/,
        ),
        attempt_capability: expect.stringMatching(
          /^[A-Za-z0-9_-]{78}$/,
        ),
      })
      expect(firstBootstrap.init.credentials).toBe('same-origin')
      expect(firstBootstrap.init.headers).not.toHaveProperty(
        'X-Atol-CSRF',
      )
      const prepared = await readAuthorizationRecord(reference!)
      expectReleasedPreparedRecord(prepared, firstBootstrap)

      const retryVault = newVault()
      await expect(retryVault.beginInteractive()).resolves.toBeUndefined()

      const bootstraps = bootstrapRequests(captured)
      expect(bootstraps).toHaveLength(3)
      expect(bootstraps[2].body).toEqual(bootstraps[1].body)
      const par = captured.find((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      )
      expect(par?.body).toMatchObject({
        tab_secret: firstBootstrap.body.tab_secret,
        cancellation_secret: firstBootstrap.body.cancellation_secret,
        par_idempotency_key: firstBootstrap.body.par_idempotency_key,
        bootstrap_attempt_capability:
          firstBootstrap.body.attempt_capability,
      })
      await expect(readAuthorizationRecord(reference!)).resolves.toMatchObject({
        id: reference,
        status: 'navigating',
        ...exactBootstrapCapabilities(firstBootstrap),
      })
    },
  )

  it.each([
    ['busy bootstrap', 409, 'busy'],
    ['unequal bootstrap capabilities', 400, 'invalid_request'],
  ] as const)(
    'retains prepared custody across a generic %s error',
    async (_label, status, error) => {
      const captured = installFetchRouter((request) => {
        if (request.url.endsWith('/bootstrap')) {
          if (!request.body.attempt_capability) {
            return bootstrapAttemptChallenge()
          }
          return jsonResponse({ error }, status)
        }
        throw new Error(`unexpected request: ${request.url}`)
      })

      await expect(start(newVault())).rejects.toThrow()

      const reference = activeReference()
      expect(reference).toBeDefined()
      const firstBootstrap = bootstrapRequests(captured)[1]
      expect(firstBootstrap.body.mode).toBe('create')
      expectReleasedPreparedRecord(
        await readAuthorizationRecord(reference!),
        firstBootstrap,
      )

      await expect(start(newVault())).rejects.toThrow()

      const bootstraps = bootstrapRequests(captured)
      expect(bootstraps).toHaveLength(3)
      expect(bootstraps[2].body).toEqual(bootstraps[1].body)
      expectReleasedPreparedRecord(
        await readAuthorizationRecord(reference!),
        firstBootstrap,
      )
    },
  )

  it('probes expired prepared custody and deletes only on authenticated terminal proof', async () => {
    let bootstrapAttempt = 0
    const captured = installFetchRouter((request) => {
      if (!request.url.endsWith('/bootstrap')) {
        throw new Error(`unexpected request: ${request.url}`)
      }
      if (!request.body.attempt_capability) {
        return bootstrapAttemptChallenge()
      }
      bootstrapAttempt++
      if (bootstrapAttempt === 1) {
        throw new TypeError('bootstrap response was lost')
      }
      if (bootstrapAttempt === 2) {
        return jsonResponse(
          { error: 'authorization_nonterminal' },
          409,
        )
      }
      if (bootstrapAttempt === 3) {
        return new Response(
          JSON.stringify({ error: 'authorization_terminal' }),
          {
            status: 410,
            headers: { 'Content-Type': 'application/json' },
          },
        )
      }
      return jsonResponse({ error: 'authorization_terminal' }, 410)
    })

    await expect(start(newVault())).rejects.toThrow()

    const reference = activeReference()
    expect(reference).toBeDefined()
    const prepared = await readAuthorizationRecord(reference!)
    const expiresAt = prepared.expiresAt
    if (typeof expiresAt !== 'number') {
      throw new Error('test prepared expiry is missing')
    }
    const now = Date.now
    Date.now = () => expiresAt

    try {
      await expect(start(newVault())).rejects.toBeInstanceOf(
        ResponseVaultAuthorizationBusyError,
      )
      expectReleasedPreparedRecord(
        await readAuthorizationRecord(reference!),
        bootstrapRequests(captured)[1],
      )

      await expect(start(newVault())).rejects.toThrow(
        /terminal classification is invalid/,
      )
      expectReleasedPreparedRecord(
        await readAuthorizationRecord(reference!),
        bootstrapRequests(captured)[0],
      )

      await expect(start(newVault())).rejects.toThrow()
    } finally {
      Date.now = now
    }

    const requests = bootstrapRequests(captured)
    expect(requests).toHaveLength(5)
    expect(requests[0].body.mode).toBe('create')
    expect(requests[1].body.mode).toBe('create')
    for (const probe of requests.slice(2)) {
      expect(probe.body).toEqual({
        ...requests[1].body,
        mode: 'terminal_only',
      })
      expect(probe.init.credentials).toBe('same-origin')
      expect(probe.init.headers).not.toHaveProperty('X-Atol-CSRF')
    }
    expectNoActiveReference()
    await expect(readAuthorizationRecord(reference!)).resolves.toBeUndefined()
    await expect(readAuthorizationSlots()).resolves.toEqual([])
  })
})
