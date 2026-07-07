/**
 * KEKVault tests.
 *
 * Scope: provision / rehydrate / clear / hasRecord, the device-key non-
 * extractability guarantee, version-skew handling, and a set of gremlin
 * inputs (wrong KEK, tampered ciphertext, oversized wrappedDEK, empty
 * inputs, clear-after-missing). Runs under fake-indexeddb for zero I/O,
 * and under Node's WebCrypto because jsdom does not ship a real
 * `crypto.subtle`.
 */
import "fake-indexeddb/auto"
import { webcrypto as nodeWebCrypto } from "node:crypto"
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest"
import { KEKVault } from "../../src/crypto/kek-vault"

function fixtureKEK(): Uint8Array {
  const b = new Uint8Array(32)
  for (let i = 0; i < 32; i++) b[i] = (i + 1) & 0xff
  return b
}

function fixtureDEK(): Uint8Array {
  const b = new Uint8Array(32)
  for (let i = 0; i < 32; i++) b[i] = (255 - i) & 0xff
  return b
}

function fixtureNonce(): Uint8Array {
  const n = new Uint8Array(12)
  for (let i = 0; i < 12; i++) n[i] = (7 * i + 3) & 0xff
  return n
}

function toBase64(bytes: Uint8Array): string {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!)
  return btoa(s)
}

async function wrapDEK(
  kek: Uint8Array,
  dek: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  const key = await nodeWebCrypto.subtle.importKey(
    "raw",
    kek,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  )
  const ciphertext = new Uint8Array(
    await nodeWebCrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, dek),
  )
  const out = new Uint8Array(nonce.length + ciphertext.length)
  out.set(nonce, 0)
  out.set(ciphertext, nonce.length)
  return toBase64(out)
}

const originalCrypto = globalThis.crypto
beforeAll(() => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: nodeWebCrypto,
  })
})
afterAll(() => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: originalCrypto,
  })
})

beforeEach(async () => {
  await new Promise<void>((resolve) => {
    const req = indexedDB.deleteDatabase("atol-sdk")
    req.onsuccess = () => resolve()
    req.onerror = () => resolve()
    req.onblocked = () => resolve()
  })
})
afterEach(async () => {
  await new Promise<void>((resolve) => {
    const req = indexedDB.deleteDatabase("atol-sdk")
    req.onsuccess = () => resolve()
    req.onerror = () => resolve()
    req.onblocked = () => resolve()
  })
})

describe("KEKVault.provision", () => {
  it("returns the unwrapped DEK", async () => {
    const kek = fixtureKEK()
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(kek, dek, fixtureNonce())
    const out = await new KEKVault().provision(new Uint8Array(kek), wrapped)
    expect(out).toEqual(dek)
  })

  it("zeroes the caller's KEK after use", async () => {
    const kek = fixtureKEK()
    const wrapped = await wrapDEK(kek, fixtureDEK(), fixtureNonce())
    const passed = new Uint8Array(kek)
    await new KEKVault().provision(passed, wrapped)
    expect(Array.from(passed).every((b) => b === 0)).toBe(true)
  })

  it("rejects when KEK does not match wrappedDEK (auth tag fails)", async () => {
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    const wrongKEK = new Uint8Array(32) // all zeros
    await expect(new KEKVault().provision(wrongKEK, wrapped)).rejects.toBeDefined()
  })

  it("rejects empty KEK input", async () => {
    await expect(
      new KEKVault().provision(new Uint8Array(0), "whatever"),
    ).rejects.toThrow(/empty/)
  })

  it("rejects empty wrappedDEK input", async () => {
    await expect(new KEKVault().provision(fixtureKEK(), "")).rejects.toThrow(/empty/)
  })

  it("rejects when wrappedDEK is shorter than nonce+tag", async () => {
    const tiny = toBase64(new Uint8Array(16))
    await expect(new KEKVault().provision(fixtureKEK(), tiny)).rejects.toBeDefined()
  })

  it("does not leave a vault record behind when the KEK is wrong", async () => {
    const vault = new KEKVault()
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    await expect(vault.provision(new Uint8Array(32), wrapped)).rejects.toBeDefined()
    // provision unwraps before persisting, so a failed unwrap leaves no
    // useless record behind.
    expect(await vault.hasRecord()).toBe(false)
  })

  it("overwrites an existing record (password rotation / user switch)", async () => {
    const vault = new KEKVault()
    const wrapped1 = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    await vault.provision(new Uint8Array(fixtureKEK()), wrapped1)

    const kek2 = new Uint8Array(32).fill(0xaa)
    const dek2 = new Uint8Array(32).fill(0x55)
    const wrapped2 = await wrapDEK(kek2, dek2, fixtureNonce())
    const out = await vault.provision(new Uint8Array(kek2), wrapped2)
    expect(out).toEqual(dek2)

    const rehydrated = await vault.rehydrate(wrapped2)
    expect(rehydrated).toEqual(dek2)
  })
})

describe("KEKVault.rehydrate", () => {
  it("unwraps the DEK from a persisted KEK without re-prompting", async () => {
    const vault = new KEKVault()
    const kek = fixtureKEK()
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(kek, dek, fixtureNonce())
    await vault.provision(new Uint8Array(kek), wrapped)
    expect(await vault.rehydrate(wrapped)).toEqual(dek)
  })

  it("returns null when the vault has no record", async () => {
    const out = await new KEKVault().rehydrate(
      await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce()),
    )
    expect(out).toBeNull()
  })

  it("rejects empty wrappedDEK input", async () => {
    const vault = new KEKVault()
    await vault.provision(
      new Uint8Array(fixtureKEK()),
      await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce()),
    )
    await expect(vault.rehydrate("")).rejects.toThrow(/empty/)
  })

  it("rejects a tampered wrappedDEK (AES-GCM auth-tag failure)", async () => {
    const vault = new KEKVault()
    const kek = fixtureKEK()
    const wrapped = await wrapDEK(kek, fixtureDEK(), fixtureNonce())
    await vault.provision(new Uint8Array(kek), wrapped)

    const raw = Uint8Array.from(atob(wrapped), (c) => c.charCodeAt(0))
    raw[20] ^= 0x01
    await expect(vault.rehydrate(toBase64(raw))).rejects.toBeDefined()
  })

  it("rejects a wrappedDEK from a different KEK", async () => {
    const vault = new KEKVault()
    await vault.provision(
      new Uint8Array(fixtureKEK()),
      await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce()),
    )
    const otherKEK = new Uint8Array(32).fill(0xcc)
    const wrappedWithOther = await wrapDEK(otherKEK, fixtureDEK(), fixtureNonce())
    await expect(vault.rehydrate(wrappedWithOther)).rejects.toBeDefined()
  })
})

describe("KEKVault.clear", () => {
  it("wipes the record so subsequent rehydrate returns null", async () => {
    const vault = new KEKVault()
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    await vault.provision(new Uint8Array(fixtureKEK()), wrapped)
    expect(await vault.hasRecord()).toBe(true)

    await vault.clear()
    expect(await vault.hasRecord()).toBe(false)
    expect(await vault.rehydrate(wrapped)).toBeNull()
  })

  it("is idempotent when no record exists", async () => {
    const vault = new KEKVault()
    await expect(vault.clear()).resolves.not.toThrow()
    await expect(vault.clear()).resolves.not.toThrow()
  })
})

describe("KEKVault.hasRecord", () => {
  it("returns false on a fresh vault", async () => {
    expect(await new KEKVault().hasRecord()).toBe(false)
  })

  it("returns true after provision", async () => {
    const vault = new KEKVault()
    await vault.provision(
      new Uint8Array(fixtureKEK()),
      await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce()),
    )
    expect(await vault.hasRecord()).toBe(true)
  })
})

describe("KEKVault when IndexedDB is unavailable", () => {
  let savedIDB: typeof indexedDB
  beforeEach(() => {
    savedIDB = globalThis.indexedDB
    // openDB rejects when indexedDB is undefined; clear() and hasRecord()
    // must degrade gracefully rather than throw.
    Object.defineProperty(globalThis, "indexedDB", {
      configurable: true,
      value: undefined,
    })
  })
  afterEach(() => {
    Object.defineProperty(globalThis, "indexedDB", {
      configurable: true,
      value: savedIDB,
    })
  })

  it("clear() is a no-op (does not throw) when IndexedDB is missing", async () => {
    await expect(new KEKVault().clear()).resolves.toBeUndefined()
  })

  it("hasRecord() returns false when IndexedDB is missing", async () => {
    expect(await new KEKVault().hasRecord()).toBe(false)
  })

  it("rehydrate() surfaces the missing-IndexedDB error", async () => {
    await expect(new KEKVault().rehydrate("some.wrapped.dek")).rejects.toThrow(
      /IndexedDB is not available/,
    )
  })
})

describe("KEKVault device key", () => {
  it("is stored as a non-extractable CryptoKey", async () => {
    const vault = new KEKVault()
    await vault.provision(
      new Uint8Array(fixtureKEK()),
      await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce()),
    )

    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open("atol-sdk", 1)
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
    })
    const rec = await new Promise<{ deviceKey: CryptoKey } | null>((resolve, reject) => {
      const tx = db.transaction("kek-vault", "readonly")
      const req = tx.objectStore("kek-vault").get("current")
      req.onsuccess = () => resolve(req.result as { deviceKey: CryptoKey } | null)
      req.onerror = () => reject(req.error)
    })
    db.close()

    expect(rec).not.toBeNull()
    expect(rec!.deviceKey.extractable).toBe(false)
    // Guarantee: exportKey on a non-extractable key must reject.
    await expect(
      crypto.subtle.exportKey("raw", rec!.deviceKey),
    ).rejects.toBeDefined()
  })
})

describe("KEKVault multi-instance", () => {
  it("two vault instances on the same origin share the same record", async () => {
    const a = new KEKVault()
    const b = new KEKVault()
    const kek = fixtureKEK()
    const wrapped = await wrapDEK(kek, fixtureDEK(), fixtureNonce())
    await a.provision(new Uint8Array(kek), wrapped)
    expect(await b.rehydrate(wrapped)).toEqual(fixtureDEK())
  })

  it("clear() on one instance affects the other", async () => {
    const a = new KEKVault()
    const b = new KEKVault()
    await a.provision(
      new Uint8Array(fixtureKEK()),
      await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce()),
    )
    await b.clear()
    expect(await a.hasRecord()).toBe(false)
  })
})
