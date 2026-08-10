/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import type { DPoPKeyManager } from '../../src/dpop/dpop'
import { createDPoPKeyManager } from '../../src/dpop/dpop'
import { bytesToBase64Url } from '../../src/crypto/base64url'
import { describe, expect, it } from 'vitest'
import {
  beginResponseVaultNavigation,
  bindResponseVaultBootstrapAttempt,
  claimResponseVaultExecution,
  claimResponseVaultNavigation,
  claimResponseVaultRejection,
  claimResponseVaultTerminalProbe,
  markResponseVaultInitializing,
  releaseResponseVaultCancellationExecution,
  ResponseVaultExecutionBusyError,
  retryResponseVaultRejection,
  stageResponseVaultAuthorization,
  type ResponseVaultAuthorization,
  type ResponseVaultSecrets,
} from '../../src/oidc/response-vault-storage'
import type {
  MutableResponseVaultCancellationRecord,
  ResponseVaultRecord,
} from '../../src/oidc/response-vault-model'
import { publicCancellation } from '../../src/oidc/response-vault-storage-custody'
import { assertExecutionClaim } from '../../src/oidc/response-vault-storage-execution'
import {
  classifyStoredRecord,
  materializeCancellationRecord,
  recordSettlement,
  slotKey,
  validCancellationRecord,
  validSlotRecord,
  validStoredRecord,
} from '../../src/oidc/response-vault-storage-validation'
import {
  BINDING,
  mutateDatabase,
} from './response-vault-adversarial-test-support'
import {
  installResponseVaultRegressionHooks,
  readAuthorizationRecord,
} from './response-vault-regression-helpers'

const OWNER_A = 'A'.repeat(43)
const OWNER_B = 'B'.repeat(43)
const TERMINAL_PROOF = bytesToBase64Url(new Uint8Array(58).fill(7))
const SECRETS: ResponseVaultSecrets = {
  state: 'C'.repeat(43),
  nonce: 'D'.repeat(43),
  codeVerifier: 'E'.repeat(43),
  codeChallenge: 'F'.repeat(43),
  tabSecret: 'G'.repeat(43),
  parIdempotencyKey: 'H'.repeat(43),
  cancellationSecret: 'I'.repeat(43),
}

installResponseVaultRegressionHooks()

async function stagePrepared(): Promise<ResponseVaultAuthorization> {
  const dpopKey = await createDPoPKeyManager()
  if (!dpopKey) throw new Error('test DPoP key is unavailable')
  return stageResponseVaultAuthorization(
    dpopKey,
    BINDING,
    'interactive',
    {},
    0,
    SECRETS,
  )
}

async function rawRecord(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultRecord> {
  return await readAuthorizationRecord(
    authorization.reference.id,
  ) as unknown as ResponseVaultRecord
}

async function replaceRecord(
  record: ResponseVaultRecord | MutableResponseVaultCancellationRecord,
): Promise<void> {
  await mutateDatabase('authorizations', (transaction) => {
    transaction.objectStore('authorizations').put(record)
  })
}

function cancellationFrom(
  source: ResponseVaultRecord,
  status: 'adopted' | 'published' = 'adopted',
) {
  return materializeCancellationRecord({
    ...source,
    status,
    transactionId: OWNER_A,
    terminalProof: TERMINAL_PROOF,
    bootstrapAttemptCapability: TERMINAL_PROOF,
    bootstrapTerminalProof: undefined,
    requestUri: undefined,
    csrfToken: OWNER_B,
    phaseExpiresAt: undefined,
    navigationOwner: undefined,
    navigationExpiresAt: undefined,
    executionOwner: undefined,
    executionExpiresAt: undefined,
  })
}

describe('response-vault stored record validation', () => {
  it('rejects primitive slots and returns exact stored error settlement', () => {
    expect(validSlotRecord(null, slotKey(BINDING))).toBe(false)
    expect(
      recordSettlement({
        settlementKind: 'error',
        settlementErrorCode: 'access_denied',
      } as ResponseVaultRecord),
    ).toEqual({ kind: 'error', errorCode: 'access_denied' })
  })

  it('rejects invalid execution, transaction, and expiry bindings', async () => {
    const authorization = await stagePrepared()
    const stored = await rawRecord(authorization)
    expect(validStoredRecord(stored, Date.now(), true)).toBe(true)
    expect(
      validStoredRecord(
        { ...stored, executionFence: -1 },
        Date.now(),
        true,
      ),
    ).toBe(false)
    expect(
      validStoredRecord(
        { ...stored, executionOwner: OWNER_A },
        Date.now(),
        true,
      ),
    ).toBe(false)
    expect(
      validStoredRecord(
        { ...stored, status: 'pushed' },
        Date.now(),
        true,
      ),
    ).toBe(false)

    const expired = {
      ...stored,
      expiresAt: Date.now() - 1,
      phaseExpiresAt: Date.now() - 1,
    }
    expect(validStoredRecord(expired, Date.now(), false)).toBe(false)
    expect(validStoredRecord(expired, Date.now(), true)).toBe(true)
  })

  it('classifies exact cancellation custody and honors explicit expiry authority', async () => {
    const authorization = await stagePrepared()
    const stored = await rawRecord(authorization)
    const cancellation = cancellationFrom(stored)
    expect(validCancellationRecord(null, Date.now())).toBe(false)
    expect(validCancellationRecord(cancellation, Date.now())).toBe(true)
    const expired = { ...cancellation, expiresAt: Date.now() - 1 }
    expect(validCancellationRecord(expired, Date.now(), false)).toBe(false)
    expect(validCancellationRecord(expired, Date.now(), true)).toBe(true)
    expect(classifyStoredRecord(null, Date.now(), true)).toBeUndefined()
    expect(
      classifyStoredRecord(cancellation, Date.now(), true),
    ).toEqual({ kind: 'cancellation', record: cancellation })
  })

  it('refuses to materialize cancellation without transaction proof', async () => {
    const authorization = await stagePrepared()
    const stored = await rawRecord(authorization)
    expect(() => materializeCancellationRecord(stored)).toThrow(
      /materialization binding is incomplete/,
    )
  })
})

describe('response-vault durable claim guards', () => {
  it('validates stage input, expected generation, and generated thumbprints', async () => {
    const dpopKey = await createDPoPKeyManager()
    if (!dpopKey) throw new Error('test DPoP key is unavailable')
    await expect(
      stageResponseVaultAuthorization(
        dpopKey,
        { ...BINDING, scope: '' },
        'interactive',
        {},
        0,
        SECRETS,
      ),
    ).rejects.toThrow(/invalid authorization input/)
    await expect(
      stageResponseVaultAuthorization(
        dpopKey,
        BINDING,
        'interactive',
        {},
        0,
        SECRETS,
        { logout: OWNER_A, tabOwner: OWNER_B },
      ),
    ).rejects.toThrow(/authority was superseded/)
    await expect(
      stageResponseVaultAuthorization(
        {
          thumbprint: async () => 'not-canonical',
        } as unknown as DPoPKeyManager,
        BINDING,
        'interactive',
        {},
        0,
        SECRETS,
      ),
    ).rejects.toThrow(/non-canonical authorization key/)
  })

  it('fails loud when an occupied slot has lost its durable record', async () => {
    const authorization = await stagePrepared()
    await mutateDatabase('authorizations', (transaction) => {
      transaction
        .objectStore('authorizations')
        .delete(authorization.reference.id)
    })
    await expect(stagePrepared()).rejects.toThrow(
      /active authorization record is missing/,
    )
  })

  it('validates navigation, execution, rejection, and terminal claim inputs', async () => {
    const authorization = await stagePrepared()
    await expect(
      beginResponseVaultNavigation(
        authorization,
        authorization.expiresAt + 1,
      ),
    ).rejects.toThrow(/invalid navigation deadline/)
    await expect(
      claimResponseVaultNavigation(
        authorization,
        'bad-owner',
        'interactive',
      ),
    ).rejects.toThrow(/invalid navigation claim/)
    await expect(
      claimResponseVaultExecution(
        authorization,
        'bad-owner',
        ['prepared'],
      ),
    ).rejects.toThrow(/invalid execution claim/)
    await expect(
      claimResponseVaultRejection(
        authorization,
        'bad-owner',
        ['prepared'],
      ),
    ).rejects.toThrow(/invalid rejection claim/)

    const stored = await rawRecord(authorization)
    const cancellation = publicCancellation(cancellationFrom(stored), 0)
    await expect(
      claimResponseVaultTerminalProbe(cancellation, 'bad-owner'),
    ).rejects.toThrow(/invalid terminal probe claim/)
  })

  it('requires exact durable status before navigation or execution claims', async () => {
    const authorization = await stagePrepared()
    await expect(
      claimResponseVaultNavigation(
        authorization,
        OWNER_A,
        'interactive',
      ),
    ).rejects.toBeInstanceOf(ResponseVaultExecutionBusyError)
    await expect(
      claimResponseVaultExecution(
        authorization,
        OWNER_B,
        ['pushed'],
      ),
    ).rejects.toBeInstanceOf(ResponseVaultExecutionBusyError)
  })

  it('rejects contradictory and non-superseding generation claims', async () => {
    const authorization = await stagePrepared()
    await expect(
      claimResponseVaultExecution(
        authorization,
        OWNER_A,
        ['prepared'],
        5_000,
        true,
        true,
        true,
      ),
    ).rejects.toThrow(/invalid generation supersession claim/)
    await expect(
      claimResponseVaultExecution(
        authorization,
        OWNER_B,
        ['prepared'],
        5_000,
        false,
        true,
        true,
      ),
    ).rejects.toBeInstanceOf(ResponseVaultExecutionBusyError)
  })

  it('distinguishes a mismatched claim from a corrupt matching lease', () => {
    expect(() =>
      assertExecutionClaim(
        {
          executionOwner: OWNER_A,
          executionFence: 1,
          executionExpiresAt: Date.now() + 5_000,
        },
        undefined,
        'test claim',
      ),
    ).toThrow(ResponseVaultExecutionBusyError)
    expect(() =>
      assertExecutionClaim(
        {
          executionOwner: OWNER_A,
          executionFence: 1,
          executionExpiresAt: undefined,
        },
        { owner: OWNER_A, fence: 1 },
        'test claim',
      ),
    ).toThrow(/execution lease is corrupt/)
  })

  it('validates transition and cancellation bindings before acquiring locks', async () => {
    const authorization = await stagePrepared()
    expect(() =>
      bindResponseVaultBootstrapAttempt(
        authorization,
        'not-canonical',
        Date.now() + 5_000,
      ),
    ).toThrow(/invalid bootstrap attempt capability/)
    await expect(
      markResponseVaultInitializing({
        ...authorization,
        binding: { ...BINDING, scope: '' },
      }),
    ).rejects.toThrow(/invalid authorization binding/)

    const stored = await rawRecord(authorization)
    const cancellation = publicCancellation(cancellationFrom(stored), 0)
    await expect(
      retryResponseVaultRejection({
        ...cancellation,
        binding: { ...BINDING, scope: '' },
      }),
    ).rejects.toThrow(/invalid cancellation binding/)
  })

  it('rejects cancellation provenance and supersession substitution', async () => {
    const authorization = await stagePrepared()
    const stored = await rawRecord(authorization)
    const cancellationRecord = cancellationFrom(stored)
    await replaceRecord(cancellationRecord)
    const cancellation = publicCancellation(cancellationRecord, 0)

    await expect(
      claimResponseVaultRejection(
        cancellation,
        OWNER_A,
        ['adopted'],
        5_000,
        true,
        false,
        false,
        'interactive_cancel',
      ),
    ).rejects.toBeInstanceOf(ResponseVaultExecutionBusyError)
    await expect(
      claimResponseVaultRejection(
        cancellation,
        OWNER_A,
        ['adopted'],
        5_000,
        true,
        false,
        true,
      ),
    ).rejects.toThrow(/invalid rejection supersession claim/)
    await expect(
      claimResponseVaultRejection(
        cancellation,
        OWNER_B,
        ['adopted'],
        5_000,
        false,
        false,
        true,
      ),
    ).rejects.toBeInstanceOf(ResponseVaultExecutionBusyError)
  })

  it('retains exact rejection lock ownership across a rejected state transition', async () => {
    const authorization = await stagePrepared()
    const stored = await rawRecord(authorization)
    const cancellationRecord = cancellationFrom(stored)
    await replaceRecord(cancellationRecord)
    const cancellation = publicCancellation(cancellationRecord, 0)
    const claimed = await claimResponseVaultRejection(
      cancellation,
      OWNER_A,
      ['adopted'],
      5_000,
      true,
      false,
    )
    await expect(
      retryResponseVaultRejection(claimed),
    ).rejects.toThrow(/state mismatch/)
    await expect(
      releaseResponseVaultCancellationExecution(claimed),
    ).resolves.toMatchObject({ status: 'rejecting' })
  })

  it('rejects a terminal probe for non-published cancellation custody', async () => {
    const authorization = await stagePrepared()
    const stored = await rawRecord(authorization)
    const cancellationRecord = cancellationFrom(stored)
    await replaceRecord(cancellationRecord)
    const cancellation = publicCancellation(cancellationRecord, 0)
    await expect(
      claimResponseVaultTerminalProbe(cancellation, OWNER_A),
    ).rejects.toBeInstanceOf(ResponseVaultExecutionBusyError)
  })
})
