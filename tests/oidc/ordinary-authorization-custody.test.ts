/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import 'fake-indexeddb/auto'
import { webcrypto as nodeWebCrypto } from 'node:crypto'
import { bytesToBase64Url } from '../../src/crypto/base64url'
import { createDPoPKeyManager, dpopKeyPair } from '../../src/dpop/dpop'
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
import { OrdinaryAuthorizationPendingError } from '../../src/oidc/ordinary-authorization'
import {
  loadOrdinaryAuthorizationInventory,
  ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE,
  validateOrdinaryAuthorizationInventory,
} from '../../src/oidc/ordinary-authorization-storage'
import { readAuthorizationCodeResponseState } from '../../src/oidc/oidc'
import {
  ORDINARY_REDIRECT_URI,
  installOrdinaryTransport,
  installOrdinaryAuthorizationLocks,
  ordinaryAdmittedResponse,
  ordinaryAttemptChallenge,
  ordinaryHarness,
  ordinaryParCalls,
  ordinaryPointerKey,
  ordinaryStart,
  putOrdinaryAuthorizationRecord,
  readOrdinaryAuthorizationRecords,
  resetOrdinaryAuthorizationDatabase,
} from './ordinary-authorization-test-support'

const originalCrypto = globalThis.crypto
const originalFetch = globalThis.fetch

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
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

afterAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: originalCrypto,
  })
  Object.defineProperty(globalThis, 'fetch', {
    configurable: true,
    value: originalFetch,
  })
})

async function admittedCallback() {
  const now = 1_800_000_000_000
  vi.spyOn(Date, 'now').mockReturnValue(now)
  const transport = installOrdinaryTransport([
    ordinaryAttemptChallenge(now + 800_000),
    ordinaryAdmittedResponse(now + 800_000),
  ])
  const flow = ordinaryHarness()
  await flow.authorization.begin(ordinaryStart(flow.generation))
  const form = new URLSearchParams(
    ordinaryParCalls(transport)[0][1].body as string,
  )
  const callback = await readAuthorizationCodeResponseState(
    flow.manager,
    `${ORDINARY_REDIRECT_URI}?code=auth-code&state=${form.get('state')}`,
  )
  return { flow, callback, transport }
}

async function expectCleanupComplete(
  flow: Awaited<ReturnType<typeof admittedCallback>>['flow'],
  stateId: string,
): Promise<void> {
  expect(await flow.manager.settings.stateStore.get(stateId)).toBeNull()
  const pointerKeys = Array.from(
    { length: sessionStorage.length },
    (_, index) => sessionStorage.key(index),
  ).filter((key) => key?.includes('ordinary-authorization'))
  expect(pointerKeys).toEqual([])
  expect(await readOrdinaryAuthorizationRecords()).toEqual([])
}

describe('ordinary callback custody state machine', () => {
  it('retains the exact code only in durable custody and recovers it off URL', async () => {
    const { flow, callback } = await admittedCallback()
    const errorLog = vi
      .spyOn(console, 'error')
      .mockImplementation(() => undefined)
    const warningLog = vi
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined)
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    const [record] = await readOrdinaryAuthorizationRecords()

    expect(record.callbackCode).toBe('auth-code')
    expect(record.callbackCodeHash).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(sessionStorage.getItem(ordinaryPointerKey())).not.toContain(
      'auth-code',
    )
    expect(JSON.stringify(errorLog.mock.calls)).not.toContain('auth-code')
    expect(JSON.stringify(warningLog.mock.calls)).not.toContain('auth-code')

    await custody.release()
    const recovered = await flow.authorization.claimPendingCallback(
      flow.generation,
    )
    expect(recovered?.callback).toMatchObject({
      code: 'auth-code',
      codeVerifier: expect.stringMatching(/^[0-9a-f]{96}$/),
      redirectUri: ORDINARY_REDIRECT_URI,
    })
    await recovered?.custody.complete()
  })

  it('rejects a non-canonical code without binding or deleting custody', async () => {
    const { flow, callback } = await admittedCallback()
    await expect(
      flow.authorization.claimCallback(
        { ...callback, code: 'auth code' },
        flow.generation,
      ),
    ).rejects.toThrow(/callback code is invalid/)
    const [record] = await readOrdinaryAuthorizationRecords()
    expect(record.callbackCode).toBeNull()
    expect(record.callbackCodeHash).toBeNull()

    const exact = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await exact.complete()
  })

  it('fails loud without Web Locks and leaves exact custody recoverable', async () => {
    const { flow, callback } = await admittedCallback()
    Object.defineProperty(navigator, 'locks', {
      configurable: true,
      value: undefined,
    })
    await expect(
      flow.authorization.claimCallback(callback, flow.generation),
    ).rejects.toThrow(/Web Locks is required/)
    const [record] = await readOrdinaryAuthorizationRecords()
    expect(record.callbackCode).toBeNull()

    installOrdinaryAuthorizationLocks()
    const exact = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await exact.complete()
  })

  it('rejects the server root before releasing corrupted DPoP custody', async () => {
    const { flow, callback } = await admittedCallback()
    const [record] = await readOrdinaryAuthorizationRecords()
    const foreign = await createDPoPKeyManager()
    if (!foreign) throw new Error('test WebCrypto is unavailable')
    record.keys = dpopKeyPair(foreign)
    await putOrdinaryAuthorizationRecord(record)

    await expect(
      flow.authorization.claimCallback(callback, flow.generation),
    ).rejects.toThrow(/unrecognized custody|DPoP key mismatch/)
    await expectCleanupComplete(flow, callback.stateId)
  })

  it('captures and rejects a signed-out code callback before cleanup', async () => {
    const { flow, callback } = await admittedCallback()
    const [record] = await readOrdinaryAuthorizationRecords()
    const foreign = await createDPoPKeyManager()
    if (!foreign) throw new Error('test WebCrypto is unavailable')
    record.keys = dpopKeyPair(foreign)
    await putOrdinaryAuthorizationRecord(record)
    const pointerKey = ordinaryPointerKey()
    sessionStorage.removeItem(pointerKey)

    await flow.authorization.discardCallback(callback, flow.generation)
    await expectCleanupComplete(flow, callback.stateId)
  })

  it('rejects exact code custody without reconstructing a missing pointer', async () => {
    const { flow, callback } = await admittedCallback()
    const pointerKey = ordinaryPointerKey()
    sessionStorage.removeItem(pointerKey)

    await flow.authorization.discardCallback(callback, flow.generation)
    await expectCleanupComplete(flow, callback.stateId)
  })

  it('requires authenticated server rejection before discarding code custody', async () => {
    const { flow, callback } = await admittedCallback()
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )

    await custody.discard()
    await expectCleanupComplete(flow, callback.stateId)
  })

  it('discards an exact terminal authorization error callback', async () => {
    const { flow, callback } = await admittedCallback()
    await flow.authorization.discardCallback(
      {
        ...callback,
        code: undefined,
        error: { code: 'access_denied' },
      },
      flow.generation,
    )
    await expectCleanupComplete(flow, callback.stateId)
  })

  it('allows one callback claimant and exact reclaim after release', async () => {
    const { flow, callback } = await admittedCallback()
    const outcomes = await Promise.allSettled([
      flow.authorization.claimCallback(callback, flow.generation),
      flow.authorization.claimCallback(callback, flow.generation),
    ])
    const winners = outcomes.filter((outcome) => outcome.status === 'fulfilled')
    const losers = outcomes.filter((outcome) => outcome.status === 'rejected')
    expect(winners).toHaveLength(1)
    expect(losers).toHaveLength(1)
    expect((losers[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      OrdinaryAuthorizationPendingError,
    )
    vi.mocked(Date.now).mockReturnValue(1_800_000_600_000)
    await expect(
      flow.authorization.claimCallback(callback, flow.generation),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    await (
      winners[0] as PromiseFulfilledResult<
        Awaited<ReturnType<typeof flow.authorization.claimCallback>>
      >
    ).value.release()

    const reclaimed = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await reclaimed.complete()
  })

  it('binds ambiguous retries to the exact authorization code', async () => {
    const { flow, callback } = await admittedCallback()
    const first = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await first.release()

    await expect(
      flow.authorization.claimCallback(
        { ...callback, code: 'substituted-code' },
        flow.generation,
      ),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const exact = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await exact.complete()
  })

  it('resumes cleanup after exact OIDC state removal fails', async () => {
    const { flow, callback } = await admittedCallback()
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    const remove = vi
      .spyOn(flow.manager.settings.stateStore, 'remove')
      .mockRejectedValueOnce(new Error('injected state removal failure'))

    await expect(custody.complete()).rejects.toThrow(
      /injected state removal failure/,
    )
    remove.mockRestore()
    await expect(
      flow.authorization.finishPendingCleanup(flow.generation),
    ).resolves.toBe(true)
    await expectCleanupComplete(flow, callback.stateId)
  })

  it('resumes cleanup after exact session pointer removal fails', async () => {
    const { flow, callback } = await admittedCallback()
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    const storagePrototype = Object.getPrototypeOf(sessionStorage) as Storage
    const originalRemove = storagePrototype.removeItem
    const remove = vi
      .spyOn(storagePrototype, 'removeItem')
      .mockImplementation(function (this: Storage, key: string) {
        if (key.includes('ordinary-authorization')) {
          throw new Error('injected pointer removal failure')
        }
        return originalRemove.call(this, key)
      })

    await expect(custody.complete()).rejects.toThrow(
      /injected pointer removal failure/,
    )
    remove.mockRestore()
    await expect(
      flow.authorization.finishPendingCleanup(flow.generation),
    ).resolves.toBe(true)
    await expectCleanupComplete(flow, callback.stateId)
  })

  it('resumes cleanup after the final IndexedDB delete fails', async () => {
    const { flow, callback } = await admittedCallback()
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    const records = await readOrdinaryAuthorizationRecords()
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('atol-sdk-browser-auth', 2)
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
    const prototype = Object.getPrototypeOf(
      database
        .transaction('ordinary-authorizations', 'readonly')
        .objectStore('ordinary-authorizations'),
    ) as IDBObjectStore
    database.close()
    const remove = vi.spyOn(prototype, 'delete').mockImplementationOnce(() => {
      throw new Error('injected IndexedDB delete failure')
    })

    await expect(custody.complete()).rejects.toThrow(
      /injected IndexedDB delete failure/,
    )
    remove.mockRestore()
    expect(records).toHaveLength(1)
    await expect(
      flow.authorization.finishPendingCleanup(flow.generation),
    ).resolves.toBe(true)
    await expectCleanupComplete(flow, callback.stateId)
  })
})

function foreignRecord(
  source: Record<string, unknown>,
  mutate: (record: Record<string, unknown>) => void,
  tabOwner = 'C'.repeat(43),
): Record<string, unknown> {
  const record: Record<string, unknown> = {
    ...source,
    credentialGeneration: {
      ...(source.credentialGeneration as Record<string, unknown>),
      tabOwner,
    },
  }
  record.slotKey = JSON.stringify([
    record.issuer,
    record.clientId,
    record.redirectUri,
    tabOwner,
  ])
  const state = JSON.parse(record.stateStorage as string) as {
    data: {
      atol_browser_auth: { tab_owner_generation: string }
    }
  }
  state.data.atol_browser_auth.tab_owner_generation = tabOwner
  record.stateStorage = JSON.stringify(state)
  mutate(record)
  return record
}

describe('ordinary custody inventory validation', () => {
  it('uses bounded cursor batches that make progress without deleting live custody', async () => {
    await admittedCallback()
    const [source] = await readOrdinaryAuthorizationRecords()
    for (
      let index = 0;
      index < ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE * 2;
      index++
    ) {
      const ownerBytes = new Uint8Array(32)
      ownerBytes[30] = Math.floor(index / 256)
      ownerBytes[31] = index % 256
      const tabOwner = bytesToBase64Url(ownerBytes)
      await putOrdinaryAuthorizationRecord(
        foreignRecord(source, () => undefined, tabOwner),
      )
    }
    const getAll = vi.spyOn(IDBObjectStore.prototype, 'getAll')

    const first = await loadOrdinaryAuthorizationInventory()
    const uncommittedRetry = await loadOrdinaryAuthorizationInventory()
    expect(
      uncommittedRetry.snapshots.map(
        (snapshot) => (snapshot as Record<string, unknown>).slotKey,
      ),
    ).toEqual(
      first.snapshots.map(
        (snapshot) => (snapshot as Record<string, unknown>).slotKey,
      ),
    )
    first.commit()
    expect(() => uncommittedRetry.commit()).toThrow()
    const second = await loadOrdinaryAuthorizationInventory()
    second.commit()
    const third = await loadOrdinaryAuthorizationInventory()
    third.commit()
    const seen = new Set(
      [...first.snapshots, ...second.snapshots, ...third.snapshots].map(
        (snapshot) => (snapshot as Record<string, unknown>).slotKey as string,
      ),
    )

    expect(first).toMatchObject({
      snapshots: {
        length: ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE,
      },
      hasMore: true,
    })
    expect(second).toMatchObject({
      snapshots: {
        length: ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE,
      },
      hasMore: true,
    })
    expect(third).toMatchObject({
      snapshots: { length: 1 },
      hasMore: false,
    })
    expect(seen).toHaveLength(
      ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE * 2 + 1,
    )
    expect(getAll).not.toHaveBeenCalled()
    getAll.mockRestore()
    expect(await readOrdinaryAuthorizationRecords()).toHaveLength(
      ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE * 2 + 1,
    )
  })

  it('keeps recognized expired server-bound custody', async () => {
    const { flow } = await admittedCallback()
    vi.mocked(Date.now).mockReturnValue(1_900_000_000_000)

    await expect(
      validateOrdinaryAuthorizationInventory(),
    ).resolves.toBeUndefined()
    expect(await readOrdinaryAuthorizationRecords()).toHaveLength(1)
    flow.authorization
  })

  it.each([
    [
      'unknown scalar',
      (record: Record<string, unknown>) => {
        record.unknown = 1
      },
    ],
    [
      'unknown CryptoKey alias',
      (record: Record<string, unknown>) => {
        record.keyAlias = (record.keys as CryptoKeyPair).privateKey
      },
    ],
    [
      'malformed binding',
      (record: Record<string, unknown>) => {
        record.clientId = ''
      },
    ],
    [
      'future version',
      (record: Record<string, unknown>) => {
        record.version = 2
      },
    ],
  ])('fails atomically on expired %s custody', async (_name, mutate) => {
    await admittedCallback()
    const [valid] = await readOrdinaryAuthorizationRecords()
    await putOrdinaryAuthorizationRecord(foreignRecord(valid, mutate))
    vi.mocked(Date.now).mockReturnValue(1_900_000_000_000)

    await expect(validateOrdinaryAuthorizationInventory()).rejects.toThrow(
      /custody|binding|unrecognized/,
    )
    expect(await readOrdinaryAuthorizationRecords()).toHaveLength(2)
  })
})
