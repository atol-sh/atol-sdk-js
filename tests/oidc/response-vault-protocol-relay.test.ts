/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import { ResponseVaultSettlementPendingError } from '../../src/oidc/response-vault'
import { NetworkError } from '../../src/oidc/token-recovery'
import {
  BOOTSTRAP_TERMINAL_PROOF,
  CLIENT_ORIGIN,
  DPOP_NONCE,
  ISSUER,
  OPAQUE_A,
  OPAQUE_C,
  OPAQUE_D,
  ORGANIZATION_ID,
  PAR_PATH,
  REDIRECT,
  REQUEST_URI,
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

describe('public response-vault protocol', () => {
  it('fences startup against logout before its first asynchronous boundary', async () => {
    installFetch([])
    const vault = newVault()
    let releaseDiscard: (() => void) | undefined
    const discard = new Promise<null>((resolve) => {
      releaseDiscard = () => resolve(null)
    })
    const internal = vault as unknown as {
      activeAuthorization(): Promise<null>
    }
    const ownershipSpy = vi
      .spyOn(internal, 'activeAuthorization')
      .mockImplementation(() => discard)

    const pending = vault.beginInteractive()
    await vi.waitFor(() => expect(ownershipSpy).toHaveBeenCalledTimes(1))
    await vault.invalidateLifecycle()
    releaseDiscard?.()

    await expect(pending).rejects.toThrow(/lifecycle was superseded/)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('pushes every authorization secret in bodies and navigates parameter-free', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
    ])
    await newVault().beginInteractive({
      prompt: 'login',
      maxAge: 0,
      acrValues: 'mfa',
      organizationId: ORGANIZATION_ID,
    })

    expect(captured.map((request) => request.url)).toEqual([
      `${CLIENT_ORIGIN}/auth/browser/v1/bootstrap`,
      `${CLIENT_ORIGIN}/auth/browser/v1/pushed-authorization-requests`,
      `${ISSUER}/auth/browser/v1/issuer-bootstrap`,
      `${ISSUER}/auth/browser/v1/authorization-init`,
    ])
    for (const request of captured) {
      expect(new URL(request.url).search).toBe('')
      expect(new URL(request.url).hash).toBe('')
      expect(request.init).toMatchObject({
        method: 'POST',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      })
    }
    const par = captured[1].body
    expect(captured[0].body).toEqual({
      version: 1,
      mode: 'create',
      tab_secret: par.tab_secret,
      cancellation_secret: par.cancellation_secret,
      par_idempotency_key: par.par_idempotency_key,
      attempt_capability: expect.stringMatching(
        /^[A-Za-z0-9_-]{78}$/,
      ),
    })
    expect(par).toMatchObject({
      version: 1,
      client_id: 'example-spa',
      redirect_uri: REDIRECT,
      response_type: 'code',
      audience: 'https://api.example.com',
      prompt: 'login',
      max_age: 0,
      acr_values: 'mfa',
      organization_id: ORGANIZATION_ID,
      code_challenge_method: 'S256',
      bootstrap_terminal_proof: BOOTSTRAP_TERMINAL_PROOF,
      bootstrap_attempt_capability:
        captured[0].body.attempt_capability,
    })
    for (const field of [
      'state',
      'nonce',
      'code_challenge',
      'dpop_jkt',
      'tab_secret',
      'par_idempotency_key',
      'cancellation_secret',
    ]) {
      expect(par[field]).toEqual(expect.stringMatching(/^[A-Za-z0-9_-]{43}$/))
    }
    expect(captured[3].body).toEqual({
      version: 1,
      request_uri: REQUEST_URI,
    })

    const pointer = activeReference()
    expect(pointer).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const record = await readAuthorizationRecord(pointer!)
    const keys = record.keys as CryptoKeyPair
    expect(keys.privateKey.extractable).toBe(false)
    expect(keys.privateKey.usages).toEqual(['sign'])
    expect(record.state).toBe(par.state)
    expect(record.nonce).toBe(par.nonce)
    expect(record.tabSecret).toBe(par.tab_secret)
    expect(record.parIdempotencyKey).toBe(par.par_idempotency_key)
    expect(record.cancellationSecret).toBe(par.cancellation_secret)
    expect(record.credentialGeneration).toEqual({
      logout: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      tabOwner: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    })
    expect(
      (record.credentialGeneration as Record<string, unknown>).logout,
    ).not.toBe(
      (record.credentialGeneration as Record<string, unknown>).tabOwner,
    )
    expect(JSON.stringify([pointer])).not.toContain(String(par.state))
    expect(JSON.stringify([pointer])).not.toContain(String(par.tab_secret))
    const serialized = JSON.stringify(captured.map((request) => request.url))
    expect(serialized).not.toContain(String(par.state))
    expect(serialized).not.toContain(String(par.nonce))
    expect(serialized).not.toContain(String(par.code_challenge))
    expect(serialized).not.toContain(OPAQUE_A)
    expect(serialized).not.toContain(REQUEST_URI)
  })

  it('uses the initiating key for one DPoP nonce retry and exact settlement authority', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse(
        {
          error: 'use_dpop_nonce',
          error_description: 'authorization server requires a nonce',
        },
        400,
        {
          'Content-Type': 'application/json; charset=utf-8',
          'DPoP-Nonce': DPOP_NONCE,
        },
      ),
      relaySuccess(),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    const grant = await vault.completeInteractive()

    const firstProof = proofParts(captured[4].body.dpop_proof)
    const secondProof = proofParts(captured[5].body.dpop_proof)
    expect(firstProof.header.jwk).toEqual(secondProof.header.jwk)
    expect(firstProof.payload.nonce).toBeUndefined()
    expect(secondProof.payload.nonce).toBe(DPOP_NONCE)
    expect(firstProof.payload.htu).toBe(`${ISSUER}/auth/token`)
    expect(firstProof.payload.htm).toBe('POST')
    expect(captured[4].body.transaction_id).toBe(OPAQUE_A)
    expect(captured[5].body.transaction_id).toBe(OPAQUE_A)

    await grant.acknowledge()
    expect(captured[6].body).toEqual({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: captured[1].body.tab_secret,
      cancellation_secret: captured[1].body.cancellation_secret,
    })
    expect(captured[6].init.headers).not.toHaveProperty('X-Atol-CSRF')
    await grant.finalize()
    await grant.completePublication()
    expectNoActiveReference()
  })

  it('accepts the RFC NQCHAR DPoP nonce alphabet without normalization', async () => {
    const nqcharNonce =
      "!#$%&'()*+-./:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse(
        {
          version: 1,
          access_token: 'access-token',
          token_type: 'DPoP',
          expires_in: 3600,
          id_token: 'id-token',
          scope: 'openid profile email',
          csrf_token: OPAQUE_D,
        },
        200,
        { 'DPoP-Nonce': nqcharNonce },
      ),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()

    const grant = await vault.completeInteractive()

    expect(grant.dpopNonce).toBe(nqcharNonce)
    await completeGrantPublication(grant)
  })

  it('recovers an ambiguous nonce-bearing relay with the same transaction and proof key', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse(
        {
          error: 'use_dpop_nonce',
          error_description: 'authorization server requires a nonce',
        },
        400,
        { 'DPoP-Nonce': DPOP_NONCE },
      ),
      new TypeError('lost nonce-bearing relay response'),
      relaySuccess(),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()

    await expect(vault.completeInteractive()).rejects.toBeInstanceOf(
      NetworkError,
    )

    const grant = await vault.completeInteractive()
    expect(captured[4].body.transaction_id).toBe(OPAQUE_A)
    expect(captured[5].body.transaction_id).toBe(OPAQUE_A)
    expect(captured[6].body.transaction_id).toBe(OPAQUE_A)
    expect(proofParts(captured[4].body.dpop_proof).header.jwk).toEqual(
      proofParts(captured[5].body.dpop_proof).header.jwk,
    )
    expect(proofParts(captured[5].body.dpop_proof).header.jwk).toEqual(
      proofParts(captured[6].body.dpop_proof).header.jwk,
    )
    expect(
      captured.filter((request) => request.url.endsWith(PAR_PATH)),
    ).toHaveLength(1)
    await completeGrantPublication(grant)
  })

  it('rejects a nonce challenge whose description is not a bounded string', async () => {
    installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse({ error: 'use_dpop_nonce', error_description: true }, 400, {
        'DPoP-Nonce': DPOP_NONCE,
      }),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()

    await expect(vault.completeInteractive()).rejects.toThrow(
      /nonce challenge is malformed/,
    )
    expectNoActiveReference()
  })

  it('recovers a lost relay response with the same transaction and proof key', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      new TypeError('connection reset'),
      relaySuccess(),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    await expect(vault.completeInteractive()).rejects.toBeInstanceOf(
      NetworkError,
    )

    const grant = await vault.completeInteractive()
    expect(captured[4].body.transaction_id).toBe(OPAQUE_A)
    expect(captured[5].body.transaction_id).toBe(OPAQUE_A)
    expect(proofParts(captured[4].body.dpop_proof).header.jwk).toEqual(
      proofParts(captured[5].body.dpop_proof).header.jwk,
    )
    expect(
      captured.filter((request) => request.url.endsWith(PAR_PATH)),
    ).toHaveLength(1)
    await completeGrantPublication(grant)
  })

  it('preserves the exact relay transaction across a temporary server failure', async () => {
    const captured = installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse({ error: 'unavailable' }, 503),
      relaySuccess(),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()
    await expect(vault.completeInteractive()).rejects.toThrow(/unavailable/)

    const grant = await vault.completeInteractive()
    expect(captured[4].body.transaction_id).toBe(OPAQUE_A)
    expect(captured[5].body.transaction_id).toBe(OPAQUE_A)
    expect(proofParts(captured[4].body.dpop_proof).header.jwk).toEqual(
      proofParts(captured[5].body.dpop_proof).header.jwk,
    )
    await completeGrantPublication(grant)
  })

  it('settles a transaction whose DPoP proof is rejected', async () => {
    installFetch([
      bootstrap(OPAQUE_A),
      pushed(),
      issuerBootstrap(OPAQUE_C),
      noContent(),
      jsonResponse(
        {
          error: 'invalid_dpop_proof',
          error_description: 'proof did not verify',
        },
        400,
      ),
      noContent(),
    ])
    const vault = newVault()
    await vault.beginInteractive()

    await expect(vault.completeInteractive()).rejects.toMatchObject({
      code: 'invalid_dpop_proof',
    })
    expectNoActiveReference()
  })

  it('retries an ambiguous acknowledgement against the parsed in-memory delivery', async () => {
    const sentinel = 'sentinel-secret-settlement-recovery'
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
    const vault = newVault()
    await vault.beginInteractive({
      returnTo: `/account?credential=${sentinel}`,
    })
    const first = await vault.completeInteractive()
    const pending = await first
      .acknowledge()
      .catch((error: unknown) => error)
    expect(pending).toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )
    if (!(pending instanceof Error)) {
      throw new Error('expected a settlement Error')
    }
    expect(Reflect.ownKeys(pending)).not.toContain('authorization')
    expect(Reflect.ownKeys(pending)).not.toContain('cause')
    expect(Reflect.get(pending, 'authorization')).toBeUndefined()
    expect(
      Reflect.ownKeys(pending)
        .map((key) =>
          String(Reflect.get(pending, key)),
        )
        .join('\n'),
    ).not.toContain(sentinel)
    expect(JSON.stringify(pending)).not.toContain(sentinel)
    expect(String(pending)).not.toContain(sentinel)

    const retained = await vault.completeInteractive()
    expect(retained).toBe(first)
    expect(
      captured.filter((request) => request.url.endsWith(PAR_PATH)),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    await retained.acknowledge()
    await retained.finalize()
    await retained.completePublication()
    expectNoActiveReference()
  })
})
