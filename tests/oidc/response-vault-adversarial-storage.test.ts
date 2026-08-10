/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it } from 'vitest'
import {
  beginResponseVaultRejection,
  bindResponseVaultAcknowledgement,
  bindResponseVaultBootstrap,
  bindResponseVaultPAR,
  discardResponseVaultAuthorization,
  discardResponseVaultCancellation,
  loadActiveResponseVaultAuthorization,
  loadActiveResponseVaultAuthorizationForRejection,
  loadResponseVaultCompensations,
  loadResponseVaultAuthorization,
  markResponseVaultInitialized,
  releaseResponseVaultAuthorization,
  ResponseVaultAuthorizationBusyError,
  stageResponseVaultAuthorization,
  type ResponseVaultAuthorization,
  validResponseVaultIntent,
} from '../../src/oidc/response-vault-storage'
import {
  BOOTSTRAP_TERMINAL_PROOF,
  OPAQUE_A,
  OPAQUE_B,
  REQUEST_URI,
  TERMINAL_PROOF,
  activeReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
} from './response-vault-regression-helpers'
import {
  BINDING,
  activeAuthorization,
  claimedUnboundPARAuthorization,
  mutateDatabase,
} from './response-vault-adversarial-test-support'

installResponseVaultRegressionHooks()

describe('response-vault adversarial recovery', () => {
  it('reports a host-wide active slot owned by another client as busy', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()

    await expect(
      loadActiveResponseVaultAuthorization(
        {
          ...BINDING,
          clientId: 'other-spa',
        },
        vault.lifecycleEpoch(),
      ),
    ).rejects.toBeInstanceOf(ResponseVaultAuthorizationBusyError)
  })

  it('fails loud when the durable slot reference is corrupt', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()

    await mutateDatabase('authorization-slots', (transaction) => {
      const store = transaction.objectStore('authorization-slots')
      const request = store.getAll()
      request.onsuccess = () => {
        const slot = request.result[0] as Record<string, unknown>
        store.put({ ...slot, referenceId: 'corrupt' })
      }
    })

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).rejects.toThrow(/active authorization slot is corrupt/)
  })

  it.each([
    ['version', 2],
    ['expiresAt', 'not-an-expiry'],
  ])(
    'does not load or overwrite a slot with a malformed %s',
    async (field, value) => {
      installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })
      const vault = newVault()
      await vault.beginInteractive()
      const authorization = await activeAuthorization(vault)

      await mutateDatabase('authorization-slots', (transaction) => {
        const store = transaction.objectStore('authorization-slots')
        const request = store.getAll()
        request.onsuccess = () => {
          const slot = request.result[0] as Record<string, unknown>
          store.put({ ...slot, [field]: value })
        }
      })

      await expect(
        loadActiveResponseVaultAuthorizationForRejection(
          BINDING,
          vault.lifecycleEpoch(),
        ),
      ).rejects.toThrow(/active authorization slot is corrupt/)
      await expect(
        stageResponseVaultAuthorization(
          authorization.dpopKey,
          BINDING,
          'interactive',
          {},
          vault.lifecycleEpoch(),
          {
            state: authorization.state,
            nonce: authorization.nonce,
            codeVerifier: authorization.codeVerifier,
            codeChallenge: authorization.codeChallenge,
            tabSecret: authorization.tabSecret,
            parIdempotencyKey: authorization.parIdempotencyKey,
            cancellationSecret: authorization.cancellationSecret,
          },
        ),
      ).rejects.toThrow(/active authorization slot is corrupt/)
    },
  )

  it.each([
    ['shorter', -1_000],
    ['longer', 1_000],
  ])(
    'does not load or overwrite a slot with a %s expiry than its record',
    async (_label, delta) => {
      installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })
      const vault = newVault()
      await vault.beginInteractive()
      const authorization = await activeAuthorization(vault)

      await mutateDatabase('authorization-slots', (transaction) => {
        const store = transaction.objectStore('authorization-slots')
        const request = store.getAll()
        request.onsuccess = () => {
          const slot = request.result[0] as Record<string, unknown>
          store.put({
            ...slot,
            expiresAt: authorization.expiresAt + delta,
          })
        }
      })

      await expect(
        loadActiveResponseVaultAuthorizationForRejection(
          BINDING,
          vault.lifecycleEpoch(),
        ),
      ).rejects.toThrow(/active authorization slot is corrupt/)
      await expect(
        stageResponseVaultAuthorization(
          authorization.dpopKey,
          BINDING,
          'interactive',
          {},
          vault.lifecycleEpoch(),
          {
            state: authorization.state,
            nonce: authorization.nonce,
            codeVerifier: authorization.codeVerifier,
            codeChallenge: authorization.codeChallenge,
            tabSecret: authorization.tabSecret,
            parIdempotencyKey: authorization.parIdempotencyKey,
            cancellationSecret: authorization.cancellationSecret,
          },
        ),
      ).rejects.toThrow(/active authorization slot is corrupt/)
    },
  )

  it.each([
    ['future record version', { version: 2 }],
    ['future record expiry', { expiresAt: 'not-an-expiry' }],
  ])('does not garbage-collect a malformed %s', async (_label, patch) => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const authorization = await activeAuthorization(vault)
    const stored = await readAuthorizationRecord(authorization.reference.id)
    await mutateDatabase(
      ['authorizations', 'authorization-slots'],
      (transaction) => {
        const records = transaction.objectStore('authorizations')
        records.delete(authorization.reference.id)
        records.put({
          ...stored,
          ...patch,
          id: 'Z'.repeat(43),
          expiresAt:
            'expiresAt' in patch ? patch.expiresAt : Date.now() + 600_000,
        })
        transaction.objectStore('authorization-slots').clear()
      },
    )

    await expect(
      stageResponseVaultAuthorization(
        authorization.dpopKey,
        BINDING,
        'interactive',
        {},
        vault.lifecycleEpoch(),
        {
          state: authorization.state,
          nonce: authorization.nonce,
          codeVerifier: authorization.codeVerifier,
          codeChallenge: authorization.codeChallenge,
          tabSecret: authorization.tabSecret,
          parIdempotencyKey: authorization.parIdempotencyKey,
          cancellationSecret: authorization.cancellationSecret,
        },
      ),
    ).rejects.toThrow(/authorization stage/)
    await expect(readAuthorizationRecord('Z'.repeat(43))).resolves.toBeDefined()
  })

  it('fails loud when a live slot points to a missing durable record', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const referenceId = activeReference()
    if (!referenceId) throw new Error('test authorization reference is missing')

    await mutateDatabase('authorizations', (transaction) => {
      transaction.objectStore('authorizations').delete(referenceId)
    })

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).rejects.toThrow(/active authorization record is missing/)
  })

  it('rejects invalid durable transitions without weakening the active record', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    await vault.beginInteractive()
    const authorization = await activeAuthorization(vault)

    expect(() =>
      bindResponseVaultBootstrap(
        authorization,
        'not-canonical',
        'not-canonical',
        Date.now() + 60_000,
      ),
    ).toThrow(/invalid bootstrap response/)
    expect(() =>
      bindResponseVaultPAR(
        authorization,
        'not-canonical',
        'urn:ietf:params:oauth:request_uri:not-canonical',
        'not-canonical',
        'not-canonical',
        Date.now() + 60_000,
        Date.now() + 600_000,
      ),
    ).toThrow(/invalid pushed authorization response/)
    expect(() =>
      bindResponseVaultAcknowledgement(authorization, 'not-canonical', {
        kind: 'success',
      }),
    ).toThrow(/invalid acknowledgement binding/)
    expect(() =>
      bindResponseVaultAcknowledgement(authorization, OPAQUE_A, {
        kind: 'success',
      }),
    ).toThrow(/acknowledgement state mismatch/)
    expect(() =>
      beginResponseVaultRejection({
        ...authorization,
        transactionId: undefined,
      }),
    ).toThrow(/rejection binding is incomplete/)
    await expect(
      markResponseVaultInitialized(authorization),
    ).rejects.toBeInstanceOf(ResponseVaultAuthorizationBusyError)
    await expect(
      releaseResponseVaultAuthorization(authorization),
    ).rejects.toBeInstanceOf(ResponseVaultAuthorizationBusyError)

    await expect(
      readAuthorizationRecord(authorization.reference.id),
    ).resolves.toMatchObject({
      status: 'navigating',
      transactionId: OPAQUE_A,
    })
  })

  it('binds terminal proof monotonically across PAR replay and cancellation', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      if (request.url.endsWith('/reject')) return noContent()
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const pending = await claimedUnboundPARAuthorization(vault)
    expect(pending).toMatchObject({
      status: 'par_pending',
      bootstrapTerminalProof: BOOTSTRAP_TERMINAL_PROOF,
      terminalProof: undefined,
    })
    const requestUriExpiresAt = Date.now() + 60_000
    const transactionExpiresAt = Date.now() + 600_000
    const pushed = await bindResponseVaultPAR(
      pending,
      OPAQUE_A,
      REQUEST_URI,
      OPAQUE_B,
      TERMINAL_PROOF,
      requestUriExpiresAt,
      transactionExpiresAt,
    )
    expect(pushed).toMatchObject({
      status: 'pushed',
      bootstrapTerminalProof: undefined,
      terminalProof: TERMINAL_PROOF,
    })
    const replayed = await bindResponseVaultPAR(
      pushed,
      OPAQUE_A,
      REQUEST_URI,
      OPAQUE_B,
      TERMINAL_PROOF,
      requestUriExpiresAt,
      transactionExpiresAt,
    )
    await expect(
      bindResponseVaultPAR(
        replayed,
        OPAQUE_A,
        REQUEST_URI,
        OPAQUE_B,
        BOOTSTRAP_TERMINAL_PROOF,
        requestUriExpiresAt,
        transactionExpiresAt,
      ),
    ).rejects.toThrow(/PAR replay binding mismatch/)

    const cancellation = await beginResponseVaultRejection(replayed)
    expect(cancellation.terminalProof).toBe(TERMINAL_PROOF)
    await expect(
      readAuthorizationRecord(cancellation.reference.id),
    ).resolves.toMatchObject({
      custody: 'cancellation',
      status: 'rejecting',
      terminalProof: TERMINAL_PROOF,
    })
    await expect(
      readAuthorizationRecord(cancellation.reference.id),
    ).resolves.not.toHaveProperty('bootstrapTerminalProof')
    await discardResponseVaultCancellation(cancellation)
  })

  it('validates durable-loader inputs and empty authority explicitly', async () => {
    await expect(
      loadActiveResponseVaultAuthorizationForRejection(BINDING, 0),
    ).resolves.toBeNull()
    await expect(
      loadActiveResponseVaultAuthorization(BINDING, 0),
    ).resolves.toBeNull()
    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        { ...BINDING, scope: '' },
        0,
      ),
    ).rejects.toThrow(/invalid authorization binding/)
    await expect(
      loadResponseVaultCompensations({ ...BINDING, scope: '' }, 0),
    ).rejects.toThrow(/invalid compensation binding/)
    await expect(
      loadResponseVaultAuthorization(
        { version: 1, id: 'not-canonical' },
        BINDING,
        0,
      ),
    ).rejects.toThrow(/invalid authorization reference/)
    await expect(
      discardResponseVaultAuthorization({
        reference: { version: 1, id: 'not-canonical' },
      } as ResponseVaultAuthorization),
    ).rejects.toThrow(/invalid authorization reference/)

    expect(
      validResponseVaultIntent(
        { returnTo: 'https://attacker.example.test/account' },
        BINDING.redirectUri,
      ),
    ).toBe(false)
  })
})
