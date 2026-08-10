/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import 'fake-indexeddb/auto'
import { webcrypto as nodeWebCrypto } from 'node:crypto'
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'
import { bytesToBase64Url } from '../../src/crypto/base64url'
import {
  authorizationCodeSHA256,
  OrdinaryAuthorizationPendingError,
  serializedOrdinaryAuthorizationIntent,
  type OrdinaryAuthorizationRecord,
} from '../../src/oidc/ordinary-authorization-model'
import {
  bindOrdinaryAuthorizationAttemptCapability,
  claimOrdinaryAuthorizationRecord,
  deleteOrdinaryAuthorizationRecordRevision,
  markOrdinaryAuthorizationCodeIssued,
  markOrdinaryAuthorizationPARSubmitted,
  releaseOrdinaryAuthorizationClaim,
  replaceOrdinaryAuthorizationRecord,
  requireOrdinaryAuthorizationRejection,
  startOrdinaryAuthorizationCleanup,
} from '../../src/oidc/ordinary-authorization-storage'
import {
  assertOrdinaryAuthorizationRecord,
  assertOrdinaryAuthorizationRecordState,
  classifyOrdinaryAuthorizationRecord,
  classifyOrdinaryAuthorizationRecordEnvelope,
} from '../../src/oidc/ordinary-authorization-validation'
import {
  installOrdinaryAuthorizationLocks,
  installOrdinaryTransport,
  ordinaryAdmittedResponse,
  ordinaryAttemptChallenge,
  ordinaryHarness,
  ordinaryStart,
  putOrdinaryAuthorizationRecord,
  readOrdinaryAuthorizationRecords,
  resetOrdinaryAuthorizationDatabase,
} from './ordinary-authorization-test-support'

const NOW = 1_800_000_000_000
const originalCrypto = globalThis.crypto

function attemptCapability(deadlineMs: number, discriminator = 0): string {
  const raw = new Uint8Array(58)
  raw[0] = 1
  raw[1] = 2
  raw[57] = discriminator
  let deadline = BigInt(deadlineMs) * 1_000_000n
  for (let index = 25; index >= 18; index--) {
    raw[index] = Number(deadline & 0xffn)
    deadline >>= 8n
  }
  return bytesToBase64Url(raw)
}

async function storedRecord(): Promise<OrdinaryAuthorizationRecord> {
  const records = await readOrdinaryAuthorizationRecords()
  expect(records).toHaveLength(1)
  return records[0] as unknown as OrdinaryAuthorizationRecord
}

async function submittedRecord(): Promise<OrdinaryAuthorizationRecord> {
  installOrdinaryTransport([new TypeError('lost PAR response')])
  const flow = ordinaryHarness()
  await expect(
    flow.authorization.begin(ordinaryStart(flow.generation)),
  ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
  return storedRecord()
}

async function admittedRecord(): Promise<OrdinaryAuthorizationRecord> {
  const rootExpiresAt = NOW + 800_000
  installOrdinaryTransport([
    ordinaryAttemptChallenge(rootExpiresAt),
    ordinaryAdmittedResponse(rootExpiresAt),
  ])
  const flow = ordinaryHarness()
  await flow.authorization.begin(ordinaryStart(flow.generation))
  return storedRecord()
}

function mutateStoredState(
  record: OrdinaryAuthorizationRecord,
  mutate: (state: Record<string, unknown>) => void,
): OrdinaryAuthorizationRecord {
  const state = JSON.parse(record.stateStorage) as Record<string, unknown>
  mutate(state)
  return { ...record, stateStorage: JSON.stringify(state) }
}

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: nodeWebCrypto,
  })
})

beforeEach(async () => {
  installOrdinaryAuthorizationLocks()
  await resetOrdinaryAuthorizationDatabase()
  localStorage.clear()
  sessionStorage.clear()
  vi.spyOn(Date, 'now').mockReturnValue(NOW)
})

afterEach(async () => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  await resetOrdinaryAuthorizationDatabase()
})

afterAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: originalCrypto,
  })
})

describe('ordinary authorization durable transition guards', () => {
  it('rejects a submitted transition bound to different form custody', async () => {
    const submitted = await submittedRecord()
    await expect(
      markOrdinaryAuthorizationPARSubmitted({
        ...submitted,
        form: `${submitted.form}&audience=substituted`,
      }),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(await storedRecord()).toEqual(submitted)
  })

  it('validates attempt authority before changing submitted custody', async () => {
    const submitted = await submittedRecord()
    await expect(
      bindOrdinaryAuthorizationAttemptCapability(
        submitted,
        'not-canonical',
        NOW + 60_000,
      ),
    ).rejects.toThrow(/attempt capability is invalid/)

    const alreadyBound = new URLSearchParams(submitted.form)
    alreadyBound.set(
      'atol_attempt_capability',
      attemptCapability(NOW + 60_000),
    )
    await expect(
      bindOrdinaryAuthorizationAttemptCapability(
        { ...submitted, form: alreadyBound.toString() },
        attemptCapability(NOW + 60_000),
        NOW + 60_000,
      ),
    ).rejects.toThrow(/attempt capability is already bound/)
  })

  it('replays an exact attempt binding and rejects a substituted retry', async () => {
    const submitted = await submittedRecord()
    const expiresAt = NOW + 60_000
    const firstCapability = attemptCapability(expiresAt)
    const bound = await bindOrdinaryAuthorizationAttemptCapability(
      submitted,
      firstCapability,
      expiresAt,
    )
    await expect(
      bindOrdinaryAuthorizationAttemptCapability(
        submitted,
        firstCapability,
        expiresAt,
      ),
    ).resolves.toEqual(bound)
    await expect(
      bindOrdinaryAuthorizationAttemptCapability(
        submitted,
        attemptCapability(expiresAt, 1),
        expiresAt,
      ),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(await storedRecord()).toEqual(bound)
  })

  it('makes admitted record binding idempotent but rejects stale form custody', async () => {
    const admitted = await admittedRecord()
    await expect(
      replaceOrdinaryAuthorizationRecord(admitted, admitted),
    ).resolves.toEqual(admitted)
    await expect(
      replaceOrdinaryAuthorizationRecord(
        { ...admitted, form: `${admitted.form}&audience=substituted` },
        admitted,
      ),
    ).rejects.toThrow(/custody was superseded/)
    expect(await storedRecord()).toEqual(admitted)
  })

  it('rejects stale rejection transitions and malformed callback code pairs', async () => {
    const admitted = await admittedRecord()
    await expect(
      requireOrdinaryAuthorizationRejection({
        ...admitted,
        form: `${admitted.form}&audience=substituted`,
      }),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(await storedRecord()).toEqual(admitted)
    await expect(
      claimOrdinaryAuthorizationRecord(admitted, 'code', null),
    ).rejects.toThrow(/callback code is invalid/)
    expect(await storedRecord()).toEqual(admitted)
  })

  it('prevents a second live callback claimant and invalid claim clocks', async () => {
    const admitted = await admittedRecord()
    const code = 'authorization-code'
    const codeHash = await authorizationCodeSHA256(code)
    const claimed = await claimOrdinaryAuthorizationRecord(
      admitted,
      code,
      codeHash,
    )
    await expect(
      claimOrdinaryAuthorizationRecord(claimed, code, codeHash),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(await storedRecord()).toEqual(claimed)

    await putOrdinaryAuthorizationRecord({ ...admitted })
    vi.spyOn(Date, 'now').mockReturnValue(Number.MAX_SAFE_INTEGER)
    await expect(
      claimOrdinaryAuthorizationRecord(admitted, code, codeHash),
    ).rejects.toThrow(/callback claim clock is invalid/)
    expect(await storedRecord()).toEqual(admitted)
  })

  it('rejects code issuance and claim release without exact live ownership', async () => {
    const admitted = await admittedRecord()
    await expect(
      markOrdinaryAuthorizationCodeIssued(admitted),
    ).rejects.toThrow(/code issuance was superseded/)
    expect(await storedRecord()).toEqual(admitted)
    await expect(
      releaseOrdinaryAuthorizationClaim(admitted),
    ).rejects.toThrow(/callback release was superseded/)
    expect(await storedRecord()).toEqual(admitted)
  })

  it('replays exact cleanup and rejects a stale cleanup transition', async () => {
    const admitted = await admittedRecord()
    const cleaning = await startOrdinaryAuthorizationCleanup(admitted)
    await expect(
      startOrdinaryAuthorizationCleanup(admitted),
    ).resolves.toEqual(cleaning)
    await expect(
      startOrdinaryAuthorizationCleanup({
        ...admitted,
        form: `${admitted.form}&audience=substituted`,
      }),
    ).rejects.toThrow(/cleanup was superseded/)
    expect(await storedRecord()).toEqual(cleaning)
  })

  it('makes exact record deletion idempotent and rejects deletion without cleanup', async () => {
    const admitted = await admittedRecord()
    await expect(
      deleteOrdinaryAuthorizationRecordRevision(admitted),
    ).rejects.toThrow(/discard was superseded/)

    const cleaning = await startOrdinaryAuthorizationCleanup(admitted)
    await deleteOrdinaryAuthorizationRecordRevision(cleaning)
    await expect(
      deleteOrdinaryAuthorizationRecordRevision(cleaning),
    ).resolves.toBeUndefined()
  })
})

describe('ordinary authorization durable record validation', () => {
  it('rejects form and server-deadline substitution', async () => {
    const admitted = await admittedRecord()
    const binding = {
      issuer: admitted.issuer,
      clientId: admitted.clientId,
      redirectUri: admitted.redirectUri,
      scope: admitted.scope,
    }

    const missingParameters = new URLSearchParams(admitted.form)
    missingParameters.delete('nonce')
    missingParameters.delete('code_challenge')
    missingParameters.sort()
    expect(() =>
      assertOrdinaryAuthorizationRecord(
        { ...admitted, form: missingParameters.toString() },
        binding,
        admitted.credentialGeneration,
        admitted.intent,
      ),
    ).toThrow(/generated form binding is invalid/)

    const changedIntent = serializedOrdinaryAuthorizationIntent({
      prompt: 'login',
      returnTo: '/settings/security',
      extraQueryParams: { audience: 'https://api.atol.test' },
      dpopEnabled: true,
      dpopRequired: true,
    })
    expect(() =>
      assertOrdinaryAuthorizationRecord(
        { ...admitted, intent: changedIntent },
        binding,
        admitted.credentialGeneration,
        changedIntent,
      ),
    ).toThrow(/custody form mismatch/)

    expect(() =>
      assertOrdinaryAuthorizationRecord(
        { ...admitted, rootExpiresAtMs: admitted.rootExpiresAtMs! + 1 },
        binding,
        admitted.credentialGeneration,
        admitted.intent,
      ),
    ).toThrow(/custody deadline mismatch/)
  })

  it('rejects malformed stored OIDC, PKCE, and application state', async () => {
    const admitted = await admittedRecord()
    await expect(
      assertOrdinaryAuthorizationRecordState(
        mutateStoredState(admitted, (state) => {
          state.request_type = 'unexpected'
        }),
      ),
    ).rejects.toThrow(/stored OIDC state is invalid/)
    await expect(
      assertOrdinaryAuthorizationRecordState(
        mutateStoredState(admitted, (state) => {
          state.code_verifier = '0'.repeat(96)
        }),
      ),
    ).rejects.toThrow(/stored PKCE state mismatch/)
    await expect(
      assertOrdinaryAuthorizationRecordState(
        mutateStoredState(admitted, (state) => {
          state.data = null
        }),
      ),
    ).rejects.toThrow(/stored application state is invalid/)
    await expect(
      assertOrdinaryAuthorizationRecordState(
        mutateStoredState(admitted, (state) => {
          const data = state.data as Record<string, unknown>
          data.atol_browser_auth = null
        }),
      ),
    ).rejects.toThrow(/stored application state is invalid/)
    await expect(
      assertOrdinaryAuthorizationRecordState(
        mutateStoredState(admitted, (state) => {
          const data = state.data as Record<string, unknown>
          const application = data.atol_browser_auth as Record<
            string,
            unknown
          >
          application.version = 2
        }),
      ),
    ).rejects.toThrow(/stored application state mismatch/)
  })

  it('classifies callback hashes and DPoP key custody exactly', async () => {
    const admitted = await admittedRecord()
    await expect(
      classifyOrdinaryAuthorizationRecordEnvelope({
        ...admitted,
        issuer: 7,
      }),
    ).rejects.toThrow(/unrecognized custody record/)
    await expect(
      classifyOrdinaryAuthorizationRecordEnvelope({
        ...admitted,
        callbackCode: 'authorization-code',
        callbackCodeHash: 'A'.repeat(43),
      }),
    ).rejects.toThrow(/unrecognized custody record/)

    if (!admitted.keys) throw new Error('test DPoP keys are unavailable')
    await expect(
      classifyOrdinaryAuthorizationRecordEnvelope({
        ...admitted,
        keys: {
          privateKey: admitted.keys.privateKey,
          publicKey: admitted.keys.privateKey,
        },
      }),
    ).rejects.toThrow(/unrecognized custody record/)

    const substitutedJkt = 'A'.repeat(43)
    const parameters = new URLSearchParams(admitted.form)
    parameters.set('dpop_jkt', substitutedJkt)
    parameters.sort()
    await expect(
      classifyOrdinaryAuthorizationRecord({
        ...admitted,
        dpopJkt: substitutedJkt,
        form: parameters.toString(),
      }),
    ).rejects.toThrow(/unrecognized custody record/)
  })
})
