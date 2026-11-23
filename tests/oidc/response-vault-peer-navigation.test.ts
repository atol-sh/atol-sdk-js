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
import { BINDING, start } from './response-vault-expiry-test-support'
import {
  CLIENT_ORIGIN,
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

describe('response-vault expired peer navigation', () => {
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
})
