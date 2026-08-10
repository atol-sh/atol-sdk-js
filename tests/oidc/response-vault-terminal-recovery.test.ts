/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it } from 'vitest'
import {
  ResponseVaultDeliveryUnavailableError,
  ResponseVaultSettlementPendingError,
} from '../../src/oidc/response-vault'
import { takeResponseVaultDeliveryReturnTo } from '../../src/oidc/response-vault-contract'
import {
  LoginRequiredError,
  OAuthProtocolError,
} from '../../src/oidc/token-recovery'
import {
  activeReference,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  OPAQUE_A,
  protocolStartResponse,
  readAuthorizationRecord,
  relaySuccess,
  terminalRelay,
  tombstone,
} from './response-vault-regression-helpers'

installResponseVaultRegressionHooks()

describe('response-vault durable terminal settlement recovery', () => {
  it.each([
    'access_denied',
    'login_required',
    'invalid_request',
  ])('re-surfaces %s after an ambiguous acknowledgement and reload', async (code) => {
    let relayCalls = 0
    let acknowledgementCalls = 0
    let rejectionCalls = 0
    let acknowledgementAdopted = false
    installFetchRouter((request) => {
      const startResponse = protocolStartResponse(request)
      if (startResponse) return startResponse
      if (request.url.endsWith('/relay')) {
        relayCalls++
        return relayCalls === 1 ? terminalRelay(code) : tombstone()
      }
      if (request.url.endsWith('/acknowledge')) {
        acknowledgementCalls++
        acknowledgementAdopted = true
        if (acknowledgementCalls <= 3) {
          throw new TypeError('the adopted 204 response was lost')
        }
        return noContent()
      }
      if (request.url.endsWith('/reject')) {
        rejectionCalls++
        return noContent()
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = newVault()
    await first.beginInteractive()

    await expect(first.completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )

    expect(acknowledgementAdopted).toBe(true)
    const reference = activeReference()
    expect(reference).toBeDefined()
    await expect(readAuthorizationRecord(reference!)).resolves.toMatchObject({
      status: 'awaiting_ack',
      settlementKind: 'error',
      settlementErrorCode: code,
      transactionId: OPAQUE_A,
    })

    const recovered = await newVault()
      .completeInteractive()
      .catch((error: unknown) => error)
    expect(recovered).toBeInstanceOf(OAuthProtocolError)
    expect(recovered).toMatchObject({ code })
    expect(recovered).not.toBeInstanceOf(
      ResponseVaultDeliveryUnavailableError,
    )
    if (code === 'login_required') {
      expect(recovered).toBeInstanceOf(LoginRequiredError)
    } else {
      expect((recovered as Error).constructor).toBe(OAuthProtocolError)
    }
    expect(relayCalls).toBe(1)
    expect(acknowledgementCalls).toBe(3)
    expect(rejectionCalls).toBe(1)
    expectNoActiveReference()
  })

  it('uses delivery-unavailable recovery only for a settled success', async () => {
    let relayCalls = 0
    let acknowledgementCalls = 0
    let rejectionCalls = 0
    let acknowledgementAdopted = false
    installFetchRouter((request) => {
      const startResponse = protocolStartResponse(request)
      if (startResponse) return startResponse
      if (request.url.endsWith('/relay')) {
        relayCalls++
        return relayCalls === 1 ? relaySuccess() : tombstone()
      }
      if (request.url.endsWith('/acknowledge')) {
        acknowledgementCalls++
        acknowledgementAdopted = true
        if (acknowledgementCalls <= 3) {
          throw new TypeError('the adopted 204 response was lost')
        }
        return noContent()
      }
      if (request.url.endsWith('/reject')) {
        rejectionCalls++
        return noContent()
      }
      throw new Error(`unexpected request: ${request.url}`)
    })
    const first = newVault()
    await first.beginInteractive({ returnTo: '/after-login' })
    const grant = await first.completeInteractive()

    await expect(grant.acknowledge()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )

    expect(acknowledgementAdopted).toBe(true)
    const reference = activeReference()
    expect(reference).toBeDefined()
    await expect(readAuthorizationRecord(reference!)).resolves.toMatchObject({
      status: 'awaiting_ack',
      settlementKind: 'success',
      transactionId: OPAQUE_A,
    })

    const recovered = await newVault()
      .completeInteractive()
      .catch((error: unknown) => error)
    expect(recovered).toBeInstanceOf(ResponseVaultDeliveryUnavailableError)
    expect(recovered).not.toBeInstanceOf(OAuthProtocolError)
    expect(recovered).not.toHaveProperty('returnTo')
    expect(
      takeResponseVaultDeliveryReturnTo(
        recovered as ResponseVaultDeliveryUnavailableError,
      ),
    ).toBe('/after-login')
    expect(
      takeResponseVaultDeliveryReturnTo(
        recovered as ResponseVaultDeliveryUnavailableError,
      ),
    ).toBeUndefined()
    expect(relayCalls).toBe(1)
    expect(acknowledgementCalls).toBe(3)
    expect(rejectionCalls).toBe(1)
    expectNoActiveReference()
  })
})
