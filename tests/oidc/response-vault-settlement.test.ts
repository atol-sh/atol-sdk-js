/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  ResponseVaultCleanupPendingError,
  ResponseVaultRejectionBlockedError,
  ResponseVaultRejectionPendingError,
} from '../../src/oidc/response-vault'
import {
  currentTabOwnerGeneration,
  rotateLogoutGeneration,
} from '../../src/oidc/credential-generation'
import {
  ResponseVaultAuthorizationBusyError,
} from '../../src/oidc/response-vault-storage'
import {
  CLIENT_ORIGIN,
  OPAQUE_A,
  TERMINAL_PROOF,
  activeReference,
  completeGrantPublication,
  discoveryResponse,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  jsonResponse,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
  readAuthorizationSlots,
  relaySuccess,
} from './response-vault-regression-helpers'

installResponseVaultRegressionHooks()

const BINDING = {
  issuer: 'https://id.example.com',
  clientId: 'example-spa',
  redirectUri: 'https://app.example.com/callback',
  audience: 'https://api.example.com',
  scope: 'openid profile email',
}

describe('response-vault publication and cancellation settlement', () => {
  it('carries exact PAR authority through publishing, finalization, and publication', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const grant = await vault.completeInteractive()
    const par = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )

    expect(par?.body).toMatchObject({
      par_idempotency_key: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      cancellation_secret: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    })

    await grant.acknowledge()
    await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
      status: 'publishing',
    })
    expect(activeReference()).toBe(reference)
    const acknowledgement = captured.find((request) =>
      request.url.endsWith('/acknowledge'),
    )
    expect(acknowledgement?.body).toEqual({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: par?.body.tab_secret,
      cancellation_secret: par?.body.cancellation_secret,
    })

    await grant.finalize()
    await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
      status: 'adopted',
    })
    expect(activeReference()).toBe(reference)
    const finalization = captured.find((request) =>
      request.url.endsWith('/finalize'),
    )
    expect(finalization?.body).toEqual({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: par?.body.tab_secret,
      cancellation_secret: par?.body.cancellation_secret,
    })
    expect(finalization?.init.headers).not.toHaveProperty('X-Atol-CSRF')

    await grant.completePublication()
    expectNoActiveReference()
    await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
      status: 'published',
    })
    await expect(readAuthorizationSlots()).resolves.toEqual([])
  })

  it('cancels an adopted family after finalization but before local publication', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const grant = await vault.completeInteractive()
    await grant.acknowledge()
    await grant.finalize()
    await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
      status: 'adopted',
    })

    await grant.reject()

    const par = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )
    const rejection = captured.find((request) =>
      request.url.endsWith('/reject'),
    )
    expect(rejection?.body).toEqual({
      version: 1,
      mode: 'reject',
      transaction_id: OPAQUE_A,
      tab_secret: par?.body.tab_secret,
      cancellation_secret: par?.body.cancellation_secret,
    })
    expect(rejection?.init.headers).not.toHaveProperty('X-Atol-CSRF')
    expectNoActiveReference()
    await expect(readAuthorizationRecord(reference)).resolves.toBeUndefined()
  })

  it('probes but does not cancel a clean published family from another live SDK instance', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      if (
        request.url.endsWith('/reject') &&
        request.body.mode === 'terminal_only'
      ) {
        return jsonResponse({ error: 'authorization_nonterminal' }, 409)
      }
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = newVault()
    await first.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const grant = await first.completeInteractive()
    await completeGrantPublication(grant)
    const published = await readAuthorizationRecord(reference)
    expect(published).toMatchObject({
      custody: 'cancellation',
      rejectionProvenance: 'internal',
      status: 'published',
    })
    expect(Object.keys(published).sort()).toEqual([
      'audience',
      'bootstrapAttemptCapability',
      'cancellationSecret',
      'clientId',
      'credentialGeneration',
      'custody',
      'executionFence',
      'expiresAt',
      'id',
      'issuer',
      'redirectUri',
      'rejectionProvenance',
      'revision',
      'scope',
      'status',
      'tabSecret',
      'terminalProof',
      'transactionId',
      'version',
    ])

    await expect(newVault().completeInteractive()).rejects.toThrow(
      /no same-tab authorization is pending/,
    )

    const probes = captured.filter((request) =>
      request.url.endsWith('/reject'),
    )
    expect(probes).toHaveLength(1)
    expect(probes[0].body).toEqual({
      version: 1,
      mode: 'terminal_only',
      client_id: 'example-spa',
      transaction_id: OPAQUE_A,
      tab_secret: published.tabSecret,
      cancellation_secret: published.cancellationSecret,
      terminal_proof: TERMINAL_PROOF,
    })
    expectNoActiveReference()
    await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
      status: 'published',
    })
  })

  it.each([
    ['terminal', 410, 'authorization_terminal', undefined],
    ['nonterminal', 409, 'authorization_nonterminal', 'no-store, private'],
  ] as const)(
    'retains published custody when a %s probe lacks exact no-store authority',
    async (_label, status, errorCode, cacheControl) => {
      const captured = installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        if (request.url.endsWith('/relay')) return relaySuccess()
        if (request.url.endsWith('/acknowledge')) return noContent()
        if (
          request.url.endsWith('/reject') &&
          request.body.mode === 'terminal_only'
        ) {
          const headers: Record<string, string> = {
            'Content-Type': 'application/json',
          }
          if (cacheControl !== undefined) {
            headers['Cache-Control'] = cacheControl
          }
          return new Response(JSON.stringify({ error: errorCode }), {
            status,
            headers,
          })
        }
        if (request.url.endsWith('/reject')) return noContent()
        throw new Error(`unexpected request: ${request.url}`)
      })
      const first = newVault()
      await first.beginInteractive()
      const reference = activeReference()
      if (!reference) {
        throw new Error('test authorization reference is missing')
      }
      const grant = await first.completeInteractive()
      await completeGrantPublication(grant)

      await expect(newVault().completeInteractive()).rejects.toBeInstanceOf(
        ResponseVaultCleanupPendingError,
      )
      expect(
        captured.filter(
          (request) =>
            request.url.endsWith('/reject') &&
            request.body.mode === 'terminal_only',
        ),
      ).toHaveLength(3)
      await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
        custody: 'cancellation',
        status: 'published',
      })
    },
  )

  it('cancels published superseded custody during signed-out startup cleanup', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = newVault()
    await first.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const grant = await first.completeInteractive()
    await completeGrantPublication(grant)
    const par = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )
    rotateLogoutGeneration(BINDING)

    await expect(
      newVault().invalidateSignedOutLifecycle(),
    ).resolves.toBeUndefined()

    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    const rejection = captured.find((request) =>
      request.url.endsWith('/reject'),
    )
    expect(rejection?.body).toEqual({
      version: 1,
      mode: 'reject',
      transaction_id: OPAQUE_A,
      tab_secret: par?.body.tab_secret,
      cancellation_secret: par?.body.cancellation_secret,
    })
    expect(rejection?.init.headers).not.toHaveProperty('X-Atol-CSRF')
    await expect(readAuthorizationRecord(reference)).resolves.toBeUndefined()
  })

  it('recovers a durable transaction in a fresh process-local lifecycle', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/acknowledge')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = newVault()
    await first.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    await expect(readAuthorizationRecord(reference)).resolves.not.toHaveProperty(
      'lifecycleEpoch',
    )

    const reloaded = newVault()
    expect(reloaded.lifecycleEpoch()).toBe(0)
    const grant = await reloaded.completeInteractive()
    await completeGrantPublication(grant)

    expect(
      captured.filter((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      ),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expectNoActiveReference()
  })

  it('keeps a host-wide slot intact when another client configuration observes it', async () => {
    const captured = installFetchRouter(
      (request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        if (request.url.endsWith('/reject')) return noContent()
        throw new Error(`unexpected request: ${request.url}`)
      },
      [
        discoveryResponse(),
        discoveryResponse({
          clientId: 'other-spa',
          redirectUri: `${CLIENT_ORIGIN}/other-callback`,
          audience: 'https://other-api.example.com',
          scope: 'openid',
        }),
      ],
    )
    const owner = newVault()
    await owner.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')

    const otherTabConfig = newVault({
      clientId: 'other-spa',
      redirectUri: `${CLIENT_ORIGIN}/other-callback`,
      audience: 'https://other-api.example.com',
      scope: 'openid',
    })
    await expect(otherTabConfig.beginInteractive()).rejects.toBeInstanceOf(
      ResponseVaultAuthorizationBusyError,
    )

    expect(activeReference()).toBe(reference)
    await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
      status: 'navigating',
      clientId: 'example-spa',
    })
    expect(
      captured.filter((request) =>
        request.url.endsWith('/pushed-authorization-requests'),
      ),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(0)
  })

  it('rejects the exact callback transaction after the logout generation changes', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const par = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )
    rotateLogoutGeneration(BINDING)

    await expect(vault.completeInteractive()).rejects.toThrow(/invalidated/)

    const rejections = captured.filter((request) =>
      request.url.endsWith('/reject'),
    )
    expect(rejections).toHaveLength(1)
    expect(rejections[0].body).toEqual({
      version: 1,
      mode: 'reject',
      transaction_id: OPAQUE_A,
      tab_secret: par?.body.tab_secret,
      cancellation_secret: par?.body.cancellation_secret,
    })
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(0)
    expectNoActiveReference()
  })

  it.each([
    [
      'non-empty 204',
      () => new Response('ambiguous', { status: 204 }),
    ],
    [
      'non-JSON gateway failure',
      () =>
        new Response('<html>gateway failure</html>', {
          status: 502,
          headers: { 'Content-Type': 'text/html' },
        }),
    ],
    [
      'unexpected status',
      () => jsonResponse({ error: 'invalid_request' }, 418),
    ],
  ])('retains rejection lineage after an ambiguous %s', async (_name, reply) => {
    let rejectionAttempts = 0
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/relay')) return relaySuccess()
      if (request.url.endsWith('/reject')) {
        rejectionAttempts++
        return reply()
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const grant = await vault.completeInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')

    await expect(grant.reject()).rejects.toBeInstanceOf(
      ResponseVaultRejectionPendingError,
    )

    expect(rejectionAttempts).toBe(3)
    await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
      status: 'reject_retry',
      transactionId: OPAQUE_A,
    })
    const par = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )
    for (const rejection of captured.filter((request) =>
      request.url.endsWith('/reject'),
    )) {
      expect(rejection.body.cancellation_secret).toBe(
        par?.body.cancellation_secret,
      )
    }
  })

  it.each([400, 403])(
    'durably blocks an exact invalid_request denial with HTTP %i',
    async (status) => {
      installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        if (request.url.endsWith('/relay')) return relaySuccess()
        if (request.url.endsWith('/reject')) {
          return jsonResponse({ error: 'invalid_request' }, status)
        }
        throw new Error(`unexpected request: ${request.url}`)
      })
      const vault = newVault()
      await vault.beginInteractive()
      const grant = await vault.completeInteractive()
      const reference = activeReference()
      if (!reference) throw new Error('test authorization reference is missing')

      await expect(grant.reject()).rejects.toBeInstanceOf(
        ResponseVaultRejectionBlockedError,
      )
      await expect(readAuthorizationRecord(reference)).resolves.toMatchObject({
        status: 'reject_blocked',
      })
      expect(activeReference()).toBe(reference)
    },
  )

  it.each([
    [
      'retries a thrown tab-owner rotation after rejection released custody',
      1,
      true,
    ],
    [
      'does not report a custody-free retry before rotation is verified',
      2,
      false,
    ],
  ] as const)('%s', async (_name, failedWrites, throwOnFailure) => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')
    const originalTabOwner = currentTabOwnerGeneration(BINDING)
    const storagePrototype = Object.getPrototypeOf(
      window.sessionStorage,
    ) as Storage
    const setItem = storagePrototype.setItem
    let tabOwnerRotationAttempts = 0
    vi.spyOn(storagePrototype, 'setItem').mockImplementation(function (
      this: Storage,
      key,
      value,
    ) {
      if (key.includes(':tab-owner:')) {
        tabOwnerRotationAttempts++
        if (tabOwnerRotationAttempts <= failedWrites) {
          if (throwOnFailure) {
            throw new Error('tab-owner rotation unavailable')
          }
          return
        }
      }
      setItem.call(this, key, value)
    })

    for (let attempt = 0; attempt < failedWrites; attempt++) {
      await expect(vault.cancelLogin()).rejects.toBeInstanceOf(
        ResponseVaultCleanupPendingError,
      )
    }

    expect(currentTabOwnerGeneration(BINDING)).toBe(originalTabOwner)
    expectNoActiveReference()
    await expect(readAuthorizationRecord(reference)).resolves.toBeUndefined()

    await expect(vault.cancelLogin()).resolves.toBeUndefined()

    expect(tabOwnerRotationAttempts).toBe(failedWrites + 1)
    expect(currentTabOwnerGeneration(BINDING)).not.toBe(originalTabOwner)
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
  })

  it('rejects exact iframe authority when lifecycle invalidation cancels the wait', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ iframeTimeoutMs: 5_000 })
    const pending = vault.authorizeInIframe({ prompt: 'none' })
    void pending.catch(() => undefined)
    await vi.waitFor(() =>
      expect(document.querySelector('iframe')).not.toBeNull(),
    )

    await vault.invalidateLifecycle()
    await expect(pending).rejects.toThrow(/superseded/)

    expect(document.querySelector('iframe')).toBeNull()
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(0)
    expectNoActiveReference()
  })

  it('refuses to treat iframe renewal custody as an abandoned login', async () => {
    const captured = installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault({ iframeTimeoutMs: 5_000 })
    const pending = vault.authorizeInIframe({ prompt: 'none' })
    void pending.catch(() => undefined)
    await vi.waitFor(() =>
      expect(document.querySelector('iframe')).not.toBeNull(),
    )

    await expect(vault.cancelLogin()).rejects.toBeInstanceOf(
      ResponseVaultAuthorizationBusyError,
    )
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(0)

    await vault.invalidateLifecycle()
    await expect(pending).rejects.toThrow(/superseded/)
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    expectNoActiveReference()
  })
})
