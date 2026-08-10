/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it } from 'vitest'
import {
  ResponseVaultGrantRejectedError,
  ResponseVaultRejectionPendingError,
} from '../../src/oidc/response-vault'
import {
  credentialGenerationForLogin,
  currentCredentialAuthority,
  rotateLogoutGeneration,
} from '../../src/oidc/credential-generation'
import {
  CLIENT_ORIGIN,
  ISSUER,
  OPAQUE_A,
  REDIRECT,
  activeReference,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
  relaySuccess,
} from './response-vault-regression-helpers'

installResponseVaultRegressionHooks()

describe('response-vault rejection settlement', () => {
  it('persists an ambiguous rejection and completes its exact retry after reload', async () => {
    let rejectionAttempts = 0
    const captured = installFetchRouter((request) => {
      const start = protocolStartResponse(request)
      if (start) return start
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
    const first = newVault()
    await first.beginInteractive()
    const grant = await first.completeInteractive()
    const reference = activeReference()
    if (!reference) throw new Error('test authorization reference is missing')

    await expect(grant.reject()).rejects.toBeInstanceOf(
      ResponseVaultRejectionPendingError,
    )
    const pending = await readAuthorizationRecord(reference)
    expect(pending).toMatchObject({
      status: 'reject_retry',
      transactionId: OPAQUE_A,
    })
    expect(pending).not.toHaveProperty('csrfToken')

    await expect(newVault().completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultGrantRejectedError,
    )
    expectNoActiveReference()

    const rejections = captured.filter((request) =>
      request.url.endsWith('/reject'),
    )
    const par = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )
    expect(rejections).toHaveLength(4)
    for (const request of rejections) {
      expect(request.body).toEqual({
        version: 1,
        mode: 'reject',
        transaction_id: OPAQUE_A,
        tab_secret: par?.body.tab_secret,
        cancellation_secret: par?.body.cancellation_secret,
      })
      expect(request.init.credentials).toBe('same-origin')
      expect(request.init.headers).not.toHaveProperty('X-Atol-CSRF')
    }
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
  })

  it('rejects initialized server authority during logout invalidation', async () => {
    const captured = installFetchRouter((request) => {
      const start = protocolStartResponse(request)
      if (start) return start
      if (request.url === `${CLIENT_ORIGIN}/auth/browser/v1/reject`) {
        return noContent()
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()

    await expect(vault.invalidateLifecycle(true)).resolves.toBeUndefined()
    expectNoActiveReference()

    const rejection = captured.at(-1)
    expect(rejection?.url).toBe(
      `${CLIENT_ORIGIN}/auth/browser/v1/reject`,
    )
    expect(rejection?.body).toMatchObject({
      version: 1,
      transaction_id: OPAQUE_A,
      cancellation_secret: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    })
    expect(rejection?.init.headers).not.toHaveProperty('X-Atol-CSRF')
  })

  it('retries signed-out application cleanup without overwriting a newer login', async () => {
    const captured = installFetchRouter((request) => {
      const start = protocolStartResponse(request)
      if (start) return start
      if (request.url === `${CLIENT_ORIGIN}/auth/browser/v1/reject`) {
        return noContent()
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const binding = {
      issuer: ISSUER,
      clientId: 'example-spa',
      redirectUri: REDIRECT,
    }
    const vault = newVault()
    await vault.beginInteractive()
    rotateLogoutGeneration(binding)
    const login = credentialGenerationForLogin(binding)

    await expect(
      vault.invalidateSignedOutLifecycle(),
    ).resolves.toBeUndefined()

    expect(currentCredentialAuthority(binding)).toEqual({
      generation: login.logout,
      signedOut: false,
    })
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
  })
})
