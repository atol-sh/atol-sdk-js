/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  credentialGenerationSnapshot,
  rotateLogoutGeneration,
  rotateTabOwnerGeneration,
} from '../../src/oidc/credential-generation'
import {
  beginResponseVaultNavigation,
  releaseResponseVaultExecution,
} from '../../src/oidc/response-vault-storage'
import type { ResponseVaultRecord } from '../../src/oidc/response-vault-model'
import { materializeCancellationRecord } from '../../src/oidc/response-vault-storage-validation'
import { BINDING, mutateDatabase, start } from './response-vault-expiry-test-support'
import {
  CLIENT_ORIGIN,
  REQUEST_URI,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  jsonResponse,
  noContent,
  newVault,
  protocolStartResponse,
  readAuthorizationRecord,
  readAuthorizationSlots,
} from './response-vault-regression-helpers'

installResponseVaultRegressionHooks()

const rejectURL = `${CLIENT_ORIGIN}/auth/browser/v1/reject`
const bootstrapURL = `${CLIENT_ORIGIN}/auth/browser/v1/bootstrap`
const parURL = `${CLIENT_ORIGIN}/auth/browser/v1/pushed-authorization-requests`

function routeTerminalProbe(probe: (body: Record<string, unknown>) => Response | Promise<Response>) {
  installFetchRouter((request) => {
    if (request.url === rejectURL) {
      return request.body.mode === 'terminal_only' ? probe(request.body) : noContent()
    }
    const protocol = protocolStartResponse(request)
    if (protocol) return protocol
    throw new Error('unexpected response-vault request')
  })
}

async function navigateThenChangeTab(expired: boolean) {
  const vault = newVault()
  const initialized = await start(vault)
  const navigating = await beginResponseVaultNavigation(initialized, initialized.expiresAt)
  // Keep the origin-wide logout generation and simulate a separate tab's
  // independently generated sessionStorage owner.
  rotateTabOwnerGeneration(BINDING)
  if (expired) vi.spyOn(Date, 'now').mockReturnValue(navigating.expiresAt + 1)
  return navigating
}

async function strandBeforePAR(stage: 'before challenge' | 'after challenge' | 'PAR response') {
  installFetchRouter((request) => {
    if (
      stage === 'before challenge' && request.url === bootstrapURL ||
      stage === 'after challenge' && request.url === bootstrapURL && request.body.attempt_capability ||
      stage === 'PAR response' && request.url === parURL
    ) {
      throw new TypeError('connection closed')
    }
    if (request.url === rejectURL) return noContent()
    const protocol = protocolStartResponse(request)
    if (protocol) return protocol
    throw new Error('unexpected response-vault request')
  })
  await expect(start(newVault())).rejects.toThrow()
  const slots = await readAuthorizationSlots()
  expect(slots).toHaveLength(1)
  const stored = await readAuthorizationRecord(String(slots[0].referenceId))
  expect(stored.status).toBe(stage === 'PAR response' ? 'par_pending' : 'prepared')
  rotateTabOwnerGeneration(BINDING)
  vi.spyOn(Date, 'now').mockReturnValue(Number(stored.expiresAt) + 1)
  return stored
}

describe('response-vault expired peer recovery', () => {
  it('probes with exact terminal authority and releases peer custody before new admission', async () => {
    const probe = vi.fn(async () => jsonResponse({ error: 'authorization_terminal' }, 410))
    routeTerminalProbe(probe)
    const expired = await navigateThenChangeTab(true)
    const generation = credentialGenerationSnapshot(BINDING)

    const replacement = await start(newVault())

    expect(probe).toHaveBeenCalledExactlyOnceWith({
      version: 1,
      mode: 'terminal_only',
      transaction_id: expired.transactionId,
      client_id: BINDING.clientId,
      tab_secret: expired.tabSecret,
      cancellation_secret: expired.cancellationSecret,
      terminal_proof: expired.terminalProof,
    })
    expect(replacement.reference.id).not.toBe(expired.reference.id)
    expect(replacement.credentialGeneration).toEqual(generation)
    expect(credentialGenerationSnapshot(BINDING)).toEqual(generation)
    await expect(readAuthorizationRecord(expired.reference.id)).resolves.toBeUndefined()
    await expect(readAuthorizationSlots()).resolves.toEqual([
      expect.objectContaining({ referenceId: replacement.reference.id }),
    ])
    await releaseResponseVaultExecution(replacement)
  })

  it.each(['live peer', 'different registration', 'different logout generation'] as const)('preserves custody without probing a %s', async (peer) => {
    const probe = vi.fn(() => jsonResponse({ error: 'authorization_terminal' }, 410))
    routeTerminalProbe(probe)
    const navigation = await navigateThenChangeTab(peer !== 'live peer')
    if (peer === 'different logout generation') rotateLogoutGeneration(BINDING)
    const next = newVault(peer === 'different registration' ? { scope: 'openid' } : {})

    await expect(start(next)).rejects.toThrow()

    expect(probe).not.toHaveBeenCalled()
    await expect(readAuthorizationRecord(navigation.reference.id)).resolves.toMatchObject({ status: 'navigating' })
  })

  it.each(['active', 'ambiguous', 'untrusted terminal'] as const)('keeps exact custody when the server response is %s', async (outcome) => {
    const probe = vi.fn(() => {
      if (outcome === 'active') return jsonResponse({ error: 'authorization_nonterminal' }, 409)
      if (outcome === 'untrusted terminal') {
        return new Response('{"error":"authorization_terminal"}', { status: 410 })
      }
      throw new TypeError('connection closed')
    })
    routeTerminalProbe(probe)
    const navigation = await navigateThenChangeTab(true)
    const before = await readAuthorizationRecord(navigation.reference.id)

    await expect(start(newVault())).rejects.toThrow()

    expect(probe).toHaveBeenCalledOnce()
    await expect(readAuthorizationRecord(navigation.reference.id)).resolves.toEqual(before)
    await expect(readAuthorizationSlots()).resolves.toEqual([
      expect.objectContaining({ referenceId: navigation.reference.id }),
    ])
  })

  it('preserves custody if browser authority changes during terminal verification', async () => {
    const probe = vi.fn(() => {
      rotateLogoutGeneration(BINDING)
      return jsonResponse({ error: 'authorization_terminal' }, 410)
    })
    routeTerminalProbe(probe)
    const navigation = await navigateThenChangeTab(true)

    await expect(start(newVault())).rejects.toThrow()

    expect(probe).toHaveBeenCalledOnce()
    await expect(readAuthorizationRecord(navigation.reference.id)).resolves.toMatchObject({ status: 'navigating' })
  })

  it.each(['before challenge', 'after challenge', 'PAR response'] as const)(
    'requires phase-specific terminal status for a tab closed at %s', async (stage) => {
      const stored = await strandBeforePAR(stage)
      const terminal = vi.fn(() => jsonResponse({ error: 'authorization_terminal' }, 410))
      const requests = installFetchRouter((request) => {
        if (request.url === bootstrapURL && (request.body.mode === 'terminal_only' || request.body.mode === 'par_terminal_only')) {
          return terminal()
        }
        if (request.url === rejectURL) return noContent()
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error('unexpected response-vault request')
      })

      const replacement = await start(newVault())

      expect(terminal).toHaveBeenCalledOnce()
      const mode = stage === 'PAR response' ? 'par_terminal_only' : 'terminal_only'
      const probeIndex = requests.findIndex(({ body }) => body.mode === mode)
      expect(probeIndex).toBe(stage === 'before challenge' ? 1 : 0)
      const probe = requests[probeIndex]
      expect(probe).toMatchObject({ url: bootstrapURL, body: {
        mode,
        tab_secret: stored.tabSecret,
        cancellation_secret: stored.cancellationSecret,
        par_idempotency_key: stored.parIdempotencyKey,
        attempt_capability: stored.bootstrapAttemptCapability ?? expect.any(String),
      } })
      if (stage === 'before challenge') {
        expect(requests[0]).toMatchObject({ url: bootstrapURL, body: {
          mode: 'create', tab_secret: stored.tabSecret,
          cancellation_secret: stored.cancellationSecret, par_idempotency_key: stored.parIdempotencyKey,
        } })
        expect(requests[0].body).not.toHaveProperty('attempt_capability')
      }
      await expect(readAuthorizationRecord(String(stored.id))).resolves.toBeUndefined()
      await releaseResponseVaultExecution(replacement)
    },
  )

  it('retains custody when a potentially committed PAR is nonterminal', async () => {
    const stored = await strandBeforePAR('PAR response')
    const requests = installFetchRouter(() => jsonResponse({ error: 'authorization_nonterminal' }, 409))

    await expect(start(newVault())).rejects.toThrow()

    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({ url: bootstrapURL, body: { mode: 'par_terminal_only' } })
    await expect(readAuthorizationRecord(String(stored.id))).resolves.toEqual(stored)
  })

  it('never falls back to bootstrap-only terminal proof for an uncertain PAR', async () => {
    const stored = await strandBeforePAR('PAR response')
    const requests = installFetchRouter(({ body }) => body.mode === 'terminal_only'
      ? jsonResponse({ error: 'authorization_terminal' }, 410)
      : jsonResponse({ error: 'invalid_request' }, 400))

    await expect(start(newVault())).rejects.toThrow()

    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({ url: bootstrapURL, body: { mode: 'par_terminal_only' } })
    await expect(readAuthorizationRecord(String(stored.id))).resolves.toEqual(stored)
  })

  it.each(['pushed', 'initializing', 'initialized', 'redeeming', 'relay_retry', 'awaiting_ack', 'publishing', 'finalizing', 'adopted'] as const)(
    'requires transaction terminal proof when a peer left the %s stage', async (status) => {
      const probe = vi.fn(() => jsonResponse({ error: 'authorization_terminal' }, 410))
      routeTerminalProbe(probe)
      const owner = await start(newVault())
      await releaseResponseVaultExecution(owner)
      const record = await readAuthorizationRecord(owner.reference.id)
      const phasePending = status === 'pushed' || status === 'initializing'
      const settlementPending = status === 'awaiting_ack' || status === 'publishing' || status === 'finalizing' || status === 'adopted'
      await mutateDatabase('authorizations', (transaction) => transaction.objectStore('authorizations').put({
        ...record,
        status,
        ...(phasePending && { requestUri: REQUEST_URI, phaseExpiresAt: owner.expiresAt }),
        ...(settlementPending && { settlementKind: 'success' }),
      }))
      rotateTabOwnerGeneration(BINDING)
      vi.spyOn(Date, 'now').mockReturnValue(owner.expiresAt + 1)

      const replacement = await start(newVault())

      expect(probe).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
        mode: 'terminal_only', transaction_id: owner.transactionId, terminal_proof: owner.terminalProof,
      }))
      await expect(readAuthorizationRecord(owner.reference.id)).resolves.toBeUndefined()
      await releaseResponseVaultExecution(replacement)
    },
  )

  it('releases expired cancellation-only custody only after transaction terminal proof', async () => {
    const probe = vi.fn(() => jsonResponse({ error: 'authorization_terminal' }, 410))
    routeTerminalProbe(probe)
    const owner = await start(newVault())
    await releaseResponseVaultExecution(owner)
    const raw = await readAuthorizationRecord(owner.reference.id)
    const record = materializeCancellationRecord(raw as unknown as ResponseVaultRecord, 'reject_retry')
    await mutateDatabase('authorizations', (transaction) => transaction.objectStore('authorizations').put(record))
    rotateTabOwnerGeneration(BINDING)
    vi.spyOn(Date, 'now').mockReturnValue(owner.expiresAt + 1)

    const replacement = await start(newVault())

    expect(probe).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
      mode: 'terminal_only', transaction_id: owner.transactionId,
    }))
    await expect(readAuthorizationRecord(owner.reference.id)).resolves.toBeUndefined()
    await releaseResponseVaultExecution(replacement)
  })
})
