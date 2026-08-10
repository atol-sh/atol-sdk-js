/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import { loadActiveResponseVaultAuthorizationForRejection } from '../../src/oidc/response-vault-storage'
import {
  BOOTSTRAP_TERMINAL_PROOF,
  installFetchRouter,
  installResponseVaultRegressionHooks,
  newVault,
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
  it('atomically aborts a collapse with two live par_pending owners', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const now = Date.now()
    const records = ['P', 'Q'].map((letter, index) => ({
      ...baseRecord,
      id: letter.repeat(43),
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
        tabOwner: (index === 0 ? 'R' : 'S').repeat(43),
      },
      createdAt: now - 1_000,
      revision: 10,
    }))
    const slots = records.map((record) => ({
      version: 1,
      key: legacyGenerationSlotKey(record),
      referenceId: record.id,
      expiresAt: record.expiresAt,
    }))
    await deleteDatabase()
    await createLegacyDatabase(2, records, slots)

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).rejects.toBeDefined()

    const legacy = await readLegacyDatabase(2)
    expect(legacy.records.map((record) => [record.id, record.status])).toEqual([
      ['P'.repeat(43), 'par_pending'],
      ['Q'.repeat(43), 'par_pending'],
    ])
    expect(legacy.slots).toEqual(slots)
  })

  it.each(['unknown status', 'malformed cancellation'] as const)(
    'atomically aborts on live %s evidence',
    async (failure) => {
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
        failure === 'unknown status' ? 'U'.repeat(43) : 'M'.repeat(43)
      const record: Record<string, unknown> = {
        ...baseRecord,
        id: migratedId,
        status:
          failure === 'unknown status' ? 'future_authority' : 'initialized',
        createdAt: now - 1_000,
        expiresAt: now + 599_000,
        revision: 10,
      }
      if (failure === 'malformed cancellation') {
        delete record.cancellationSecret
        delete record.keys
      }
      const slot = {
        version: 1,
        key: legacyGenerationSlotKey(record),
        referenceId: migratedId,
        expiresAt: record.expiresAt,
      }
      await deleteDatabase()
      await createLegacyDatabase(2, [record], [slot])

      await expect(
        loadActiveResponseVaultAuthorizationForRejection(
          BINDING,
          vault.lifecycleEpoch(),
        ),
      ).rejects.toBeDefined()

      const legacy = await readLegacyDatabase(2)
      expect(legacy.records).toEqual([record])
      expect(legacy.slots).toEqual([slot])
    },
  )

  it.each(['extra scalar', 'aliased CryptoKey'] as const)(
    'atomically aborts on a live legacy record with an %s member',
    async (memberKind) => {
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
        memberKind === 'extra scalar' ? 'S'.repeat(43) : 'K'.repeat(43)
      const memberName =
        memberKind === 'extra scalar' ? 'unexpectedAuthority' : 'aliasedKey'
      const keys = baseRecord.keys as CryptoKeyPair
      const memberValue =
        memberKind === 'extra scalar' ? 'smuggled' : keys.privateKey
      const record: Record<string, unknown> = {
        ...baseRecord,
        id: migratedId,
        status: 'initialized',
        createdAt: now - 1_000,
        expiresAt: now + 599_000,
        revision: 10,
        [memberName]: memberValue,
      }
      const slot = {
        version: 1,
        key: legacyGenerationSlotKey(record),
        referenceId: migratedId,
        expiresAt: record.expiresAt,
      }
      await deleteDatabase()
      await createLegacyDatabase(2, [record], [slot])

      await expect(
        loadActiveResponseVaultAuthorizationForRejection(
          BINDING,
          vault.lifecycleEpoch(),
        ),
      ).rejects.toBeDefined()

      const legacy = await readLegacyDatabase(2)
      expect(legacy.records).toHaveLength(1)
      expect(legacy.records[0]).toHaveProperty(memberName)
      if (memberKind === 'extra scalar') {
        expect(legacy.records[0][memberName]).toBe('smuggled')
      } else {
        expect(legacy.records[0][memberName]).toMatchObject({
          type: 'private',
          extractable: false,
          usages: ['sign'],
        })
      }
      expect(legacy.slots).toEqual([slot])
    },
  )

  it('prefers a unique v3 origin owner over a generation-scoped peer', async () => {
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const now = Date.now()
    const originOwner = {
      ...baseRecord,
      id: 'Z'.repeat(43),
      status: 'initialized',
      transactionId: 'T'.repeat(43),
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'R'.repeat(43),
      },
      createdAt: now - 1_000,
      expiresAt: now + 300_000,
      revision: 10,
    }
    const generationPeer = {
      ...baseRecord,
      id: 'A'.repeat(43),
      status: 'initialized',
      transactionId: 'U'.repeat(43),
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
      3,
      [originOwner, generationPeer],
      [
        {
          version: 1,
          key: originSlotKey(),
          referenceId: originOwner.id,
          expiresAt: originOwner.expiresAt,
        },
        {
          version: 1,
          key: legacyGenerationSlotKey(generationPeer),
          referenceId: generationPeer.id,
          expiresAt: generationPeer.expiresAt,
        },
      ],
    )

    await expect(
      loadActiveResponseVaultAuthorizationForRejection(
        BINDING,
        vault.lifecycleEpoch(),
      ),
    ).resolves.toMatchObject({
      reference: { id: originOwner.id },
      status: 'initialized',
      expiresAt: originOwner.expiresAt,
    })
    await expect(readAuthorizationSlots()).resolves.toEqual([
      expect.objectContaining({
        referenceId: originOwner.id,
        expiresAt: originOwner.expiresAt,
      }),
    ])
    await expect(
      readAuthorizationRecord(generationPeer.id),
    ).resolves.toMatchObject({
      custody: 'cancellation',
      status: 'reject_retry',
      transactionId: generationPeer.transactionId,
      expiresAt: generationPeer.expiresAt,
    })
  })

  it('discards equality-expired custody without extending live migration deadlines', async () => {
    const now = Date.parse('2026-07-24T12:00:00.000Z')
    vi.spyOn(Date, 'now').mockReturnValue(now)
    installFetchRouter((request) => {
      const protocol = protocolStartResponse(request)
      if (protocol) return protocol
      throw new Error(`unexpected request: ${request.url}`)
    })
    const vault = newVault()
    const base = await start(vault)
    const baseRecord = await readAuthorizationRecord(base.reference.id)
    const owner = {
      ...baseRecord,
      id: 'X'.repeat(43),
      status: 'initialized',
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'R'.repeat(43),
      },
      createdAt: now - 1_000,
      expiresAt: now + 1_000,
      revision: 10,
    }
    const loser = {
      ...baseRecord,
      id: 'Y'.repeat(43),
      status: 'initialized',
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'S'.repeat(43),
      },
      createdAt: now - 1_000,
      expiresAt: now + 500,
      revision: 10,
    }
    const expired = {
      ...baseRecord,
      id: 'E'.repeat(43),
      status: 'initialized',
      credentialGeneration: {
        ...(baseRecord.credentialGeneration as Record<string, unknown>),
        tabOwner: 'T'.repeat(43),
      },
      createdAt: now - 1_000,
      expiresAt: now,
      revision: 10,
    }
    await deleteDatabase()
    await createLegacyDatabase(
      2,
      [owner, loser, expired],
      [owner, loser, expired].map((record) => ({
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
      reference: { id: owner.id },
      expiresAt: now + 1_000,
    })
    await expect(readAuthorizationSlots()).resolves.toEqual([
      expect.objectContaining({
        referenceId: owner.id,
        expiresAt: now + 1_000,
      }),
    ])
    await expect(readAuthorizationRecord(loser.id)).resolves.toMatchObject({
      custody: 'cancellation',
      status: 'reject_retry',
      expiresAt: now + 500,
    })
    await expect(readAuthorizationRecord(expired.id)).resolves.toMatchObject({
      custody: 'cancellation',
      status: 'reject_retry',
      transactionId: baseRecord.transactionId,
      expiresAt: now,
    })
  })

  it.each([
    ['wrong key', { key: JSON.stringify([1, 'https://wrong.example']) }],
    ['wrong expiry', { expiresAt: Date.now() + 598_000 }],
  ])(
    'aborts migration on live legacy slot evidence with a %s',
    async (_label, slotPatch) => {
      installFetchRouter((request) => {
        const protocol = protocolStartResponse(request)
        if (protocol) return protocol
        throw new Error(`unexpected request: ${request.url}`)
      })
      const vault = newVault()
      const base = await start(vault)
      const baseRecord = await readAuthorizationRecord(base.reference.id)
      const now = Date.now()
      const migratedId = 'M'.repeat(43)
      const migratedRecord = {
        ...baseRecord,
        id: migratedId,
        status: 'initialized',
        createdAt: now - 1_000,
        expiresAt: now + 599_000,
        revision: 10,
      }
      await deleteDatabase()
      await createLegacyDatabase(
        2,
        [migratedRecord],
        [
          {
            version: 1,
            key: legacyGenerationSlotKey(migratedRecord),
            referenceId: migratedId,
            expiresAt: now + 599_000,
            ...slotPatch,
          },
        ],
      )

      await expect(
        loadActiveResponseVaultAuthorizationForRejection(
          BINDING,
          vault.lifecycleEpoch(),
        ),
      ).rejects.toBeDefined()
    },
  )
})
