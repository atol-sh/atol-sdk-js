/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  ResponseVaultDeliveryUnavailableError,
  ResponseVaultGrantRejectedError,
  ResponseVaultRejectionPendingError,
  ResponseVaultSettlementPendingError,
} from '../../src/oidc/response-vault'
import { ResponseVaultAuthorizationBusyError } from '../../src/oidc/response-vault-storage'
import { LoginRequiredError, NetworkError } from '../../src/oidc/token-recovery'
import { installResponseVaultLockManager } from './response-vault-lock-test-support'
import {
  BOOTSTRAP_TERMINAL_PROOF,
  CLIENT_ORIGIN,
  ISSUER,
  OPAQUE_A,
  OPAQUE_C,
  OPAQUE_D,
  PAR_PATH,
  REDIRECT,
  activeReference,
  bootstrap,
  completeGrantPublication,
  expectNoActiveReference,
  installFetch,
  installResponseVaultProtocolHooks,
  issuerBootstrap,
  jsonResponse,
  newVault,
  noContent,
  proofParts,
  pushed,
  readAuthorizationRecord,
  relaySuccess,
} from './response-vault-protocol-test-support'

installResponseVaultProtocolHooks()

async function expectPreparedBootstrapCustody(): Promise<void> {
  const reference = activeReference()
  expect(reference).toBeDefined()
  const record = await readAuthorizationRecord(reference!)
  expect(record).toMatchObject({ status: 'prepared' })
  expect(record?.executionOwner).toBeUndefined()
  expect(record?.executionExpiresAt).toBeUndefined()
}

describe('public response-vault protocol', () => {
  it('revokes an in-memory delivery after an ambiguous acknowledgement and reload', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      new TypeError('lost 204'),
      new TypeError('lost 204 again'),
      new TypeError('lost 204 finally'),
      noContent(),
    ])
    const firstVault = newVault()
    await firstVault.beginInteractive()
    const first = await firstVault.completeInteractive()
    await expect(first.acknowledge()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )

    await expect(newVault().completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultDeliveryUnavailableError,
    )
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expect(captured[8].url).toBe(`${CLIENT_ORIGIN}/auth/browser/v1/reject`)
    expectNoActiveReference()
  })

  it('recovers a persisted redeeming transaction after a page crash', async () => {
    let releaseAbandonedRelay: ((response: Response) => void) | undefined
    const abandonedRelay = new Promise<Response>((resolve) => {
      releaseAbandonedRelay = resolve
    })
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      () => abandonedRelay,
      relaySuccess(),
      noContent(),
    ])
    const firstVault = newVault()
    await firstVault.beginInteractive()
    const abandonedCompletion = firstVault.completeInteractive()
    void abandonedCompletion.catch(() => undefined)
    await vi.waitFor(() =>
      expect(
        captured.filter((request) => request.url.endsWith('/relay')),
      ).toHaveLength(1),
    )
    const pointer = activeReference()!
    await expect(readAuthorizationRecord(pointer)).resolves.toMatchObject({
      status: 'redeeming',
    })
    await expect(newVault().completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultAuthorizationBusyError,
    )
    // Replacing the manager models execution-context teardown. A wall-clock
    // lease change alone cannot steal authority while the browser still
    // holds the exclusive Web Lock.
    installResponseVaultLockManager()

    const recoveredGrant = await newVault().completeInteractive()
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(2)
    expect(captured[4].body.transaction_id).toBe(OPAQUE_A)
    expect(captured[5].body.transaction_id).toBe(OPAQUE_A)
    expect(proofParts(captured[4].body.dpop_proof).header.jwk).toEqual(
      proofParts(captured[5].body.dpop_proof).header.jwk,
    )
    await completeGrantPublication(recoveredGrant)
    expectNoActiveReference()

    releaseAbandonedRelay?.(relaySuccess())
    await expect(abandonedCompletion).rejects.toThrow()
  })

  it('cancels acknowledgement lineage after reload without persisting bearer material', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      new TypeError('lost 204'),
      new TypeError('lost 204 again'),
      new TypeError('lost 204 finally'),
      noContent(),
    ])
    const firstVault = newVault()
    await firstVault.beginInteractive()
    const first = await firstVault.completeInteractive()
    await expect(first.acknowledge()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )

    await expect(newVault().completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultDeliveryUnavailableError,
    )
    expect(captured[8].url).toBe(`${CLIENT_ORIGIN}/auth/browser/v1/reject`)
    expect(captured[8].body.cancellation_secret).toBe(
      captured[1].body.cancellation_secret,
    )
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expectNoActiveReference()
  })

  it('preserves acknowledgement lineage after an ambiguous cancellation transport', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      new TypeError('lost 204'),
      new TypeError('lost 204 again'),
      new TypeError('lost 204 finally'),
      new TypeError('lost rejection response'),
      new TypeError('lost rejection response again'),
      new TypeError('lost rejection response finally'),
      noContent(),
    ])
    const firstVault = newVault()
    await firstVault.beginInteractive()
    const first = await firstVault.completeInteractive()
    await expect(first.acknowledge()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )

    await expect(newVault().completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultRejectionPendingError,
    )
    const pointer = activeReference()!
    await expect(readAuthorizationRecord(pointer)).resolves.toMatchObject({
      status: 'reject_retry',
    })

    await expect(newVault().completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultGrantRejectedError,
    )
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(4)
    expectNoActiveReference()
  })

  it('acknowledges a terminal vault result before surfacing it', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse(
        { version: 1, error: 'login_required', csrf_token: OPAQUE_D },
        400,
      ),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    await expect(vault.completeInteractive()).rejects.toBeInstanceOf(
      LoginRequiredError,
    )
    expect(captured[5].url).toBe(`${CLIENT_ORIGIN}/auth/browser/v1/acknowledge`)
    expectNoActiveReference()
  })

  it('retries acknowledgement of a parsed terminal result without another relay', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse(
        { version: 1, error: 'login_required', csrf_token: OPAQUE_D },
        400,
      ),
      new TypeError('lost terminal acknowledgement'),
      new TypeError('lost terminal acknowledgement again'),
      new TypeError('lost terminal acknowledgement finally'),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    await expect(vault.completeInteractive()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )

    await expect(vault.completeInteractive()).rejects.toBeInstanceOf(
      LoginRequiredError,
    )
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expectNoActiveReference()
  })

  it('retries a temporarily unavailable acknowledgement without re-relaying', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      jsonResponse({ error: 'unavailable' }, 503),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    const grant = await vault.completeInteractive()

    await grant.acknowledge()
    await grant.finalize()
    await grant.completePublication()
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/acknowledge')),
    ).toHaveLength(2)
    expectNoActiveReference()
  })

  it('rejects a non-adopted grant after a terminal acknowledgement response', async () => {
    installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      jsonResponse({ error: 'invalid_request' }, 400),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    const grant = await vault.completeInteractive()

    await expect(grant.acknowledge()).rejects.toMatchObject({
      code: 'invalid_request',
    })
    await grant.reject()
    expectNoActiveReference()
  })

  it('does not settle an already acknowledged grant twice', async () => {
    installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    const grant = await vault.completeInteractive()
    await completeGrantPublication(grant)

    await expect(grant.acknowledge()).rejects.toThrow(/already settled/)
    await expect(grant.reject()).resolves.toBeUndefined()
  })

  it('rejects duplicate response members before creating authority', async () => {
    const captured = installFetch([
      jsonResponse(
        `{"version":1,"version":1,"csrf_token":"${OPAQUE_A}","expires_in":60}`,
        201,
      ),
    ])
    await expect(newVault().beginInteractive()).rejects.toThrow(
      /duplicate member/,
    )
    expect(captured).toHaveLength(1)
    await expectPreparedBootstrapCustody()
  })

  it.each([
    [
      'a non-JSON content type',
      new Response('{}', {
        status: 201,
        headers: { 'Content-Type': 'text/plain' },
      }),
      /content type is invalid/,
    ],
    [
      'an unavailable bootstrap',
      jsonResponse({ error: 'unavailable' }, 503),
      /OAuth protocol error: temporarily_unavailable/,
    ],
    [
      'a busy bootstrap',
      jsonResponse({ error: 'busy' }, 409),
      /OAuth protocol error: temporarily_unavailable/,
    ],
    [
      'a malformed error code',
      jsonResponse({ error: 7 }, 400),
      /malformed error/,
    ],
    [
      'a malformed bootstrap envelope',
      jsonResponse({ version: 1, csrf_token: 'short', expires_in: 60 }, 201),
      /bootstrap response is invalid/,
    ],
    [
      'an invalid bootstrap expiry',
      jsonResponse(
        {
          version: 1,
          csrf_token: OPAQUE_A,
          expires_in: 0,
          bootstrap_terminal_proof: BOOTSTRAP_TERMINAL_PROOF,
        },
        201,
      ),
      /bootstrap expiry is invalid/,
    ],
  ])('rejects %s', async (_name, response, expected) => {
    installFetch([response])
    await expect(newVault().beginInteractive()).rejects.toThrow(expected)
    await expectPreparedBootstrapCustody()
  })

  it('classifies a failed response-body read as a transport error', async () => {
    const response = new Response(
      new ReadableStream({
        start(controller) {
          controller.error(new TypeError('body stream reset'))
        },
      }),
      {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      },
    )
    installFetch([response])

    await expect(newVault().beginInteractive()).rejects.toBeInstanceOf(
      NetworkError,
    )
    await expectPreparedBootstrapCustody()
  })

  it('uses a fresh authorization JKT after the prior grant is acknowledged', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      noContent(),
      jsonResponse({ error: 'authorization_terminal' }, 410),
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    const first = await vault.completeInteractive()
    await completeGrantPublication(first)
    await vault.beginInteractive()
    const pars = captured.filter((request) => request.url.endsWith(PAR_PATH))
    expect(pars).toHaveLength(2)
    expect(pars[0].body.dpop_jkt).not.toBe(pars[1].body.dpop_jkt)
  })

  it('invalidates the pending handle before a delayed callback can relay', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    await vault.invalidateLifecycle()
    await expect(vault.completeInteractive()).rejects.toThrow(
      /no same-tab authorization is pending/,
    )
    expect(captured).toHaveLength(5)
    expect(captured[4].url).toBe(`${CLIENT_ORIGIN}/auth/browser/v1/reject`)
  })

  it('observes only the exact clean iframe callback without postMessage data', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      relaySuccess(),
      noContent(),
    ])
    const nativeCreateElement = document.createElement.bind(document)
    const iframe = nativeCreateElement('iframe')
    Object.defineProperty(iframe, 'contentWindow', {
      configurable: true,
      value: { location: { href: REDIRECT } },
    })
    vi.spyOn(document, 'createElement').mockImplementation(((
      tagName: string,
    ) =>
      tagName.toLowerCase() === 'iframe'
        ? iframe
        : nativeCreateElement(tagName)) as typeof document.createElement)
    const addEventListener = vi.spyOn(window, 'addEventListener')

    const vault = newVault()
    const pending = vault.authorizeInIframe({ prompt: 'none' })
    await vi.waitFor(() => expect(iframe.parentNode).toBe(document.body))
    expect(iframe.src).toBe(`${ISSUER}/auth/authorize`)
    expect(new URL(iframe.src).search).toBe('')
    expect(iframe.referrerPolicy).toBe('no-referrer')
    expect(
      iframe.getAttribute('data-atol-response-vault-owned'),
    ).toBe('')
    const frameDescriptor = Object.getOwnPropertyDescriptor(
      window,
      'frameElement',
    )
    Object.defineProperty(window, 'frameElement', {
      configurable: true,
      value: iframe,
    })
    try {
      expect(vault.isOwnedIframeCallback()).toBe(true)
      window.history.replaceState({}, '', '/not-the-callback')
      expect(vault.isOwnedIframeCallback()).toBe(false)
      window.history.replaceState({}, '', '/callback')
      Object.defineProperty(window, 'frameElement', {
        configurable: true,
        value: nativeCreateElement('iframe'),
      })
      expect(vault.isOwnedIframeCallback()).toBe(false)
      await expect(vault.completeInteractive()).rejects.toThrow(
        'response vault: callback transaction mode mismatch',
      )
      expect(
        captured.filter((request) => request.url.endsWith('/relay')),
      ).toHaveLength(0)
      await expect(
        readAuthorizationRecord(activeReference()!),
      ).resolves.toMatchObject({
        mode: 'iframe',
        status: 'navigating',
      })
    } finally {
      if (frameDescriptor) {
        Object.defineProperty(window, 'frameElement', frameDescriptor)
      }
    }
    iframe.dispatchEvent(new Event('load'))

    const grant = await pending
    expect(
      addEventListener.mock.calls.some(([name]) => name === 'message'),
    ).toBe(false)
    expect(captured[4].body).not.toHaveProperty('code')
    expect(captured[4].body).not.toHaveProperty('state')
    expect(iframe.parentNode).toBeNull()
    await completeGrantPublication(grant)
  })

  it('surfaces a settled iframe login_required result without rejecting it again', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse(
        { version: 1, error: 'login_required', csrf_token: OPAQUE_D },
        400,
      ),
      noContent(),
    ])
    const nativeCreateElement = document.createElement.bind(document)
    const iframe = nativeCreateElement('iframe')
    Object.defineProperty(iframe, 'contentWindow', {
      configurable: true,
      value: { location: { href: REDIRECT } },
    })
    vi.spyOn(document, 'createElement').mockImplementation(((
      tagName: string,
    ) =>
      tagName.toLowerCase() === 'iframe'
        ? iframe
        : nativeCreateElement(tagName)) as typeof document.createElement)

    const pending = newVault().authorizeInIframe({ prompt: 'none' })
    await vi.waitFor(() => expect(iframe.parentNode).toBe(document.body))
    iframe.dispatchEvent(new Event('load'))

    await expect(pending).rejects.toBeInstanceOf(LoginRequiredError)
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/acknowledge')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/finalize')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(0)
    expectNoActiveReference()
  })
})
