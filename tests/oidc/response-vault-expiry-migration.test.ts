/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import { ResponseVaultGrantRejectedError } from '../../src/oidc/response-vault'
import {
  loadActiveResponseVaultAuthorizationForRejection,
  loadResponseVaultLifecycleCancellations,
} from '../../src/oidc/response-vault-storage'
import {
  BOOTSTRAP_TERMINAL_PROOF,
  TERMINAL_PROOF,
  expectNoActiveReference,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
  noContent,
  protocolStartResponse,
  readAuthorizationRecord,
  readAuthorizationSlots,
} from './response-vault-regression-helpers'
import {
  BINDING,
  createLegacyDatabase,
  deleteDatabase,
  legacyGenerationSlotKey,
  originSlotKey,
  readLegacyDatabase,
  start,
} from './response-vault-expiry-test-support'

installResponseVaultRegressionHooks()

describe('response-vault server deadline custody', () => {
  it('streams more than one batch through legacy migration without getAll', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const now = Date.now()
    const records = Array.from({ length: 70 }, (_, index) => ({
      ...baseRecord,
      id: index.toString(36).padStart(43, '0'),
      status: 'published',
      settlementKind: 'success',
      createdAt: now - 1_000,
      expiresAt: now + 599_000,
      revision: index + 10,
    }))
    await deleteDatabase()
    await createLegacyDatabase(2, records, [])
    const getAll = vi.spyOn(IDBObjectStore.prototype, 'getAll')

    const first = await loadResponseVaultLifecycleCancellations(
      BINDING,
      vault.lifecycleEpoch(),
      'application',
    )
    expect(first.errors).toEqual([])
    first.commit()
    const second = await loadResponseVaultLifecycleCancellations(
      BINDING,
      vault.lifecycleEpoch(),
      'application',
    )
    expect(second.errors).toEqual([])
    second.commit()

    expect(
      new Set(
        [...first.cancellations, ...second.cancellations].map(
          (cancellation) => cancellation.reference.id,
        ),
      ),
    ).toHaveLength(70)
    expect(getAll).not.toHaveBeenCalled()
    getAll.mockRestore()
    await deleteDatabase()
  })

  it.each(['publishing', 'finalizing', 'adopted'] as const)(
    'migrates live v2 %s custody while retiring prepared local-only state',
    async (status) => {
      installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        if (request.url.endsWith('/reject')) return noContent()
        throw new Error(`unexpected request: ${request.url}`)
      })
      const vault = newVault()
      const base = await start(vault)
      const baseRecord = await readAuthorizationRecord(base.reference.id)
      const now = Date.now()
      const migratedId = status[0].toUpperCase().repeat(43)
      const expiredPrePARId = 'E'.repeat(43)
      await deleteDatabase()
      await createLegacyDatabase(
        2,
        [
          {
            ...baseRecord,
            id: migratedId,
            status,
            settlementKind: 'success',
            createdAt: now - 1_000,
            expiresAt: now + 599_000,
            revision: 20,
          },
          {
            ...baseRecord,
            id: expiredPrePARId,
            status: 'prepared',
            transactionId: undefined,
            requestUri: undefined,
            csrfToken: undefined,
            bootstrapTerminalProof: undefined,
            terminalProof: undefined,
            settlementKind: undefined,
            settlementErrorCode: undefined,
            createdAt: now - 120_000,
            expiresAt: now + 480_000,
            revision: 2,
          },
        ],
        [
          {
            version: 1,
            key: originSlotKey(),
            referenceId: migratedId,
            expiresAt: now + 599_000,
          },
        ],
      )
      sessionStorage.setItem('atol:response-vault:v1:active', migratedId)

      await expect(
        loadActiveResponseVaultAuthorizationForRejection(
          BINDING,
          vault.lifecycleEpoch(),
        ),
      ).resolves.toMatchObject({
        reference: { id: migratedId },
        status,
        settlement: { kind: 'success' },
      })
      expect(await readAuthorizationRecord(expiredPrePARId)).toBeUndefined()
      const [migratedSlot] = await readAuthorizationSlots()
      expect(migratedSlot).toMatchObject({
        referenceId: migratedId,
        expiresAt: now + 599_000,
      })
    },
  )

  it.each([
    [2, 'generation'],
    [2, 'origin'],
    [3, 'origin'],
  ] as const)(
    'migrates the historical v%i %s-scoped slot encoding exactly',
    async (version, encoding) => {
      installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })
      const vault = newVault()
      const base = await start(vault)
      const baseRecord = await readAuthorizationRecord(base.reference.id)
      const now = Date.now()
      const migratedId =
        encoding === 'generation' ? 'G'.repeat(43) : 'O'.repeat(43)
      const migratedRecord = {
        ...baseRecord,
        id: migratedId,
        status: 'initialized',
        createdAt: now - 1_000,
        expiresAt: now + 599_000,
        revision: 12,
      }
      await deleteDatabase()
      await createLegacyDatabase(
        version,
        [migratedRecord],
        [
          {
            version: 1,
            key:
              encoding === 'generation'
                ? legacyGenerationSlotKey(migratedRecord)
                : originSlotKey(),
            referenceId: migratedId,
            expiresAt: now + 599_000,
          },
        ],
      )

      await expect(
        loadActiveResponseVaultAuthorizationForRejection(
          BINDING,
          vault.lifecycleEpoch(),
        ),
      ).resolves.toMatchObject({
        reference: { id: migratedId },
        status: 'initialized',
      })
      await expect(readAuthorizationSlots()).resolves.toEqual([
        expect.objectContaining({
          key: originSlotKey(),
          referenceId: migratedId,
          expiresAt: now + 599_000,
        }),
      ])
    },
  )

  it('retains proofless live v4 custody when the v5 upgrade fails closed', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    expect(baseRecord.terminalProof).toBe(TERMINAL_PROOF)
    const now = Date.now()
    const prooflessRecord: Record<string, unknown> = {
      ...baseRecord,
      id: 'V'.repeat(43),
      status: 'initialized',
      createdAt: now - 1_000,
      expiresAt: now + 599_000,
      revision: 12,
    }
    delete prooflessRecord.bootstrapTerminalProof
    delete prooflessRecord.terminalProof
    const slot = {
      version: 1,
      key: originSlotKey(),
      referenceId: prooflessRecord.id,
      expiresAt: prooflessRecord.expiresAt,
    }
    await deleteDatabase()
    await createLegacyDatabase(4, [prooflessRecord], [slot])

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).rejects.toBeDefined()

    const retained = await readLegacyDatabase(4)
    expect(retained.records).toEqual([prooflessRecord])
    expect(retained.slots).toEqual([slot])
  })

  it('keeps ambiguous legacy adopted custody adopted when no slot exists', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const now = Date.now()
    const migratedId = 'A'.repeat(43)
    await deleteDatabase()
    await createLegacyDatabase(
      3,
      [
        {
          ...baseRecord,
          id: migratedId,
          status: 'adopted',
          settlementKind: 'success',
          createdAt: now - 1_000,
          expiresAt: now + 599_000,
          revision: 20,
        },
      ],
      [],
    )

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).resolves.toBeNull()
    await expect(readAuthorizationRecord(migratedId)).resolves.toMatchObject({
      status: 'adopted',
    })
    await expect(readAuthorizationSlots()).resolves.toEqual([])
  })

  it('demotes an exact v2 collision behind one deterministic origin barrier', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const now = Date.now()
    const first = {
      ...baseRecord,
      id: 'X'.repeat(43),
      status: 'initialized',
      transactionId: 'T'.repeat(43),
      tabSecret: 'U'.repeat(43),
      cancellationSecret: 'V'.repeat(43),
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'R'.repeat(43),
      },
      createdAt: now - 1_000,
      expiresAt: now + 599_000,
      revision: 10,
    }
    const second = {
      ...baseRecord,
      id: 'Y'.repeat(43),
      status: 'initialized',
      transactionId: 'W'.repeat(43),
      tabSecret: 'Q'.repeat(43),
      cancellationSecret: 'Z'.repeat(43),
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'S'.repeat(43),
      },
      createdAt: now - 1_000,
      expiresAt: now + 599_000,
      revision: 10,
    }
    await deleteDatabase()
    await createLegacyDatabase(
      2,
      [first, second],
      [first, second].map((record) => ({
        version: 1,
        key: legacyGenerationSlotKey(record),
        referenceId: record.id,
        expiresAt: record.expiresAt,
      })),
    )

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).resolves.toMatchObject({
      reference: { id: first.id },
      status: 'initialized',
      transactionId: first.transactionId,
    })
    await expect(readAuthorizationSlots()).resolves.toEqual([
      expect.objectContaining({
        key: originSlotKey(),
        referenceId: first.id,
        expiresAt: first.expiresAt,
      }),
    ])
    const loser = await readAuthorizationRecord(second.id)
    expect(loser).toMatchObject({
      custody: 'cancellation',
      status: 'reject_retry',
      transactionId: second.transactionId,
      tabSecret: second.tabSecret,
      cancellationSecret: second.cancellationSecret,
      expiresAt: second.expiresAt,
      credentialGeneration: second.credentialGeneration,
    })
    for (const field of [
      'keys',
      'jkt',
      'state',
      'nonce',
      'codeVerifier',
      'codeChallenge',
      'csrfToken',
      'requestUri',
    ]) {
      expect(loser).not.toHaveProperty(field)
    }
    const batch = await loadResponseVaultLifecycleCancellations(
      BINDING,
      vault.lifecycleEpoch(),
      'application',
    )
    expect(batch.errors).toEqual([])
    expect(batch.cancellations).toHaveLength(1)
    expect(batch.cancellations[0]).toMatchObject({
      reference: { version: 1, id: second.id },
      transactionId: second.transactionId,
    })
  })

  it('converts legacy navigating custody to exact rejection without discovery', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const now = Date.now()
    const migratedId = 'N'.repeat(43)
    const transactionId = 'T'.repeat(43)
    const tabSecret = 'U'.repeat(43)
    const cancellationSecret = 'V'.repeat(43)
    const navigating = {
      ...baseRecord,
      id: migratedId,
      status: 'navigating',
      transactionId,
      tabSecret,
      cancellationSecret,
      createdAt: now - 1_000,
      expiresAt: now + 599_000,
      revision: 10,
    }
    await deleteDatabase()
    await createLegacyDatabase(
      2,
      [navigating],
      [
        {
          version: 1,
          key: legacyGenerationSlotKey(navigating),
          referenceId: migratedId,
          expiresAt: navigating.expiresAt,
        },
      ],
    )

    let discoveryAttempts = 0
    const rejections: Array<Record<string, unknown>> = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input)
        if (url === `${BINDING.issuer}/.well-known/openid-configuration`) {
          discoveryAttempts++
          throw new TypeError('discovery is unavailable')
        }
        if (
          url ===
          `${new URL(BINDING.redirectUri).origin}/auth/browser/v1/reject`
        ) {
          rejections.push(
            JSON.parse(String(init?.body)) as Record<string, unknown>,
          )
          return noContent()
        }
        throw new Error(`unexpected migration recovery fetch ${url}`)
      }),
    )

    await expect(newVault().beginInteractive()).rejects.toBeInstanceOf(
      ResponseVaultGrantRejectedError,
    )

    expect(discoveryAttempts).toBe(0)
    expect(rejections).toEqual([
      {
        version: 1,
        mode: 'reject',
        transaction_id: transactionId,
        tab_secret: tabSecret,
        cancellation_secret: cancellationSecret,
      },
    ])
    await expect(readAuthorizationRecord(migratedId)).resolves.toBeUndefined()
    await expect(readAuthorizationSlots()).resolves.toEqual([])
    expectNoActiveReference()
  })

  it('retains one exact par_pending owner and demotes its transaction-bound peer', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const now = Date.now()
    const parId = 'P'.repeat(43)
    const peerId = 'I'.repeat(43)
    const parPending = {
      ...baseRecord,
      id: parId,
      status: 'par_pending',
      transactionId: undefined,
      requestUri: undefined,
      bootstrapTerminalProof: BOOTSTRAP_TERMINAL_PROOF,
      terminalProof: undefined,
      settlementKind: undefined,
      settlementErrorCode: undefined,
      phaseExpiresAt: now + 60_000,
      expiresAt: now + 60_000,
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'R'.repeat(43),
      },
      createdAt: now - 1_000,
      revision: 10,
    }
    const peer = {
      ...baseRecord,
      id: peerId,
      status: 'initialized',
      transactionId: 'J'.repeat(43),
      tabSecret: 'K'.repeat(43),
      cancellationSecret: 'L'.repeat(43),
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'S'.repeat(43),
      },
      createdAt: now - 1_000,
      expiresAt: now + 599_000,
      revision: 10,
    }
    await deleteDatabase()
    await createLegacyDatabase(
      2,
      [parPending, peer],
      [parPending, peer].map((record) => ({
        version: 1,
        key: legacyGenerationSlotKey(record),
        referenceId: record.id,
        expiresAt: record.expiresAt,
      })),
    )

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).resolves.toMatchObject({
      reference: { id: parId },
      status: 'par_pending',
      transactionId: undefined,
      expiresAt: parPending.expiresAt,
    })
    await expect(readAuthorizationSlots()).resolves.toEqual([
      expect.objectContaining({
        key: originSlotKey(),
        referenceId: parId,
        expiresAt: parPending.expiresAt,
      }),
    ])
    await expect(readAuthorizationRecord(peerId)).resolves.toMatchObject({
      custody: 'cancellation',
      status: 'reject_retry',
      transactionId: peer.transactionId,
      tabSecret: peer.tabSecret,
      cancellationSecret: peer.cancellationSecret,
      expiresAt: peer.expiresAt,
    })
  })
})
