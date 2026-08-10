/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it } from 'vitest'
import { ResponseVaultSettlementPendingError } from '../../src/oidc/response-vault'
import { createDPoPKeyManager, dpopKeyPair } from '../../src/dpop/dpop'
import {
  claimResponseVaultExecution,
  claimResponseVaultNavigation,
  loadActiveResponseVaultAuthorization,
  loadResponseVaultAuthorization,
  loadResponseVaultAuthorizationForRejection,
  releaseResponseVaultExecution,
  resetResponseVaultRelay,
  ResponseVaultAuthorizationBusyError,
} from '../../src/oidc/response-vault-storage'
import { rotateLogoutGeneration } from '../../src/oidc/credential-generation'
import { NetworkError, OAuthProtocolError } from '../../src/oidc/token-recovery'
import {
  OPAQUE_A,
  activeReference,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  jsonResponse,
  newVault,
  noContent,
  protocolStartResponse,
  pushed,
  readAuthorizationRecord,
  relaySuccess,
} from './response-vault-regression-helpers'
import {
  BINDING,
  activeAuthorization,
  replaceStoredKeys,
} from './response-vault-adversarial-test-support'

installResponseVaultRegressionHooks()

describe('response-vault adversarial recovery', () => {
  it('retries an idempotent PAR after temporary unavailability', async () => {
    let parAttempts = 0
    const captured = installFetchRouter((request) => {
      if (request.url.endsWith('/pushed-authorization-requests')) {
        parAttempts++
        if (parAttempts === 1) {
          return jsonResponse({ error: 'unavailable' }, 503)
        }
        return pushed()
      }
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })

    await newVault().beginInteractive({
      prompt: 'login',
      maxAge: 120,
      acrValues: 'urn:example:loa:2',
      organizationId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    })

    const requests = captured.filter((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )
    expect(requests).toHaveLength(2)
    expect(requests[1].body).toEqual(requests[0].body)
    expect(requests[0].body).toMatchObject({
      prompt: 'login',
      max_age: 120,
      acr_values: 'urn:example:loa:2',
      organization_id: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    })
  })

  it.each([
    [409, 'busy', ResponseVaultAuthorizationBusyError],
    [400, 'invalid_request', OAuthProtocolError],
  ])(
    'fails closed on terminal PAR HTTP %i without retaining local authority',
    async (status, code, expectedType) => {
      installFetchRouter((request) => {
        if (request.url.endsWith('/pushed-authorization-requests')) {
          return jsonResponse({ error: code }, status)
        }
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })

      await expect(newVault().beginInteractive()).rejects.toBeInstanceOf(
        expectedType,
      )

      expectNoActiveReference()
    },
  )

  it('discards pre-transaction custody only after exact terminal PAR proof', async () => {
    installFetchRouter((request) => {
      if (request.url.endsWith('/pushed-authorization-requests')) {
        return jsonResponse({ error: 'authorization_terminal' }, 410)
      }
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })

    await expect(newVault().beginInteractive()).rejects.toThrow(
      /authenticated terminal authorization/,
    )
    expectNoActiveReference()
  })

  it.each([
    ['missing', undefined],
    ['weak', 'private'],
    ['combined', 'no-store, private'],
  ] as const)(
    'retains exact PAR retry custody when terminal proof has %s Cache-Control',
    async (_label, cacheControl) => {
      installFetchRouter((request) => {
        if (request.url.endsWith('/pushed-authorization-requests')) {
          const headers: Record<string, string> = {
            'Content-Type': 'application/json',
          }
          if (cacheControl !== undefined) {
            headers['Cache-Control'] = cacheControl
          }
          return new Response(
            JSON.stringify({ error: 'authorization_terminal' }),
            { status: 410, headers },
          )
        }
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })

      await expect(newVault().beginInteractive()).rejects.toBeInstanceOf(
        NetworkError,
      )
      const reference = activeReference()
      expect(reference).toMatch(/^[A-Za-z0-9_-]{43}$/)
      const record = await readAuthorizationRecord(reference as string)
      expect(record).toMatchObject({ status: 'par_pending' })
      expect(record).not.toHaveProperty('transactionId')
    },
  )

  it('releases physical execution locks after post-commit key validation fails', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const navigating = await activeAuthorization(vault)
    const navigationOwner = navigating.navigationOwner
    if (!navigationOwner) {
      throw new Error('test navigation owner is missing')
    }
    const stored = await readAuthorizationRecord(navigating.reference.id)
    const replacement = await createDPoPKeyManager()
    if (!replacement) {
      throw new Error('test DPoP key creation failed')
    }
    const mismatchedKeys = dpopKeyPair(replacement)

    await replaceStoredKeys(navigating.reference.id, mismatchedKeys)
    await expect(
      claimResponseVaultNavigation(navigating, navigationOwner, 'interactive'),
    ).rejects.toThrow(/stored key thumbprint mismatch/)

    await replaceStoredKeys(navigating.reference.id, stored.keys)
    let current = await loadResponseVaultAuthorizationForRejection(
      navigating.reference,
      BINDING,
      vault.lifecycleEpoch(),
    )
    current = await claimResponseVaultExecution(current, 'R'.repeat(43), [
      'redeeming',
    ])

    await replaceStoredKeys(current.reference.id, mismatchedKeys)
    await expect(resetResponseVaultRelay(current)).rejects.toThrow(
      /stored key thumbprint mismatch/,
    )

    await replaceStoredKeys(current.reference.id, stored.keys)
    const retry = await loadResponseVaultAuthorizationForRejection(
      current.reference,
      BINDING,
      vault.lifecycleEpoch(),
    )
    const reclaimed = await claimResponseVaultExecution(retry, 'S'.repeat(43), [
      'relay_retry',
    ])
    await releaseResponseVaultExecution(reclaimed)
  })

  it('loads durable authority under current generation and rejection authority after rotation', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) throw new Error('test authorization reference is missing')
    const reference = { version: 1, id: referenceId } as const

    await expect(
      loadResponseVaultAuthorization(
        reference,
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).resolves.toMatchObject({
      status: 'navigating',
      transactionId: OPAQUE_A,
    })
    await expect(
      loadActiveResponseVaultAuthorization(BINDING, vault.lifecycleEpoch()),
    ).resolves.toMatchObject({
      reference,
      status: 'navigating',
    })

    rotateLogoutGeneration(BINDING)

    await expect(
      loadResponseVaultAuthorization(
        reference,
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).rejects.toThrow(/invalidated/)
    await expect(
      loadResponseVaultAuthorizationForRejection(
        reference,
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).resolves.toMatchObject({
      reference,
      transactionId: OPAQUE_A,
    })
  })

  it('retries an ambiguous finalization on the same in-memory grant', async () => {
    let finalizationAttempts = 0
    const captured = installFetchRouter((request) => {
      if (request.url.endsWith('/finalize')) {
        finalizationAttempts++
        if (finalizationAttempts <= 3) {
          throw new TypeError('finalization connection reset')
        }
        return noContent()
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
    if (!referenceId) throw new Error('test authorization reference is missing')
    const grant = await vault.completeInteractive()
    await grant.acknowledge()

    await expect(grant.finalize()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )
    await expect(readAuthorizationRecord(referenceId)).resolves.toMatchObject({
      status: 'finalizing',
      transactionId: OPAQUE_A,
    })

    await grant.finalize()
    await expect(readAuthorizationRecord(referenceId)).resolves.toMatchObject({
      status: 'adopted',
      transactionId: OPAQUE_A,
    })
    await grant.completePublication()

    expect(finalizationAttempts).toBe(4)
    expect(
      captured.filter((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      ),
    ).toHaveLength(1)
    expectNoActiveReference()
  })
})
