/**
 * Device-bound KEK vault.
 *
 * Purpose: persist the KEK across page reloads and silent-auth refreshes
 * without exposing it on disk in plaintext.
 *
 * Design: at first login we receive the KEK bytes in the URL fragment
 * (`#atol_enc_key=...`). We generate a non-extractable AES-GCM CryptoKey
 * in WebCrypto (the "device key"), encrypt the raw KEK under that device
 * key, and persist the ciphertext + IV + the CryptoKey handle itself in
 * IndexedDB. On any subsequent page load or silent refresh we can load
 * the device key handle and decrypt the stored KEK -- purely locally,
 * no round-trip and no password prompt.
 *
 * Threat model:
 *   - The device key is `extractable: false`, so an attacker with JS
 *     execution on the origin can *use* it (decrypt under the handle)
 *     but cannot copy the key bytes off the device.
 *   - The wrapped KEK ciphertext is AES-GCM, so tampering is detected
 *     by the auth tag.
 *   - IndexedDB is origin-scoped, so cross-origin scripts cannot reach
 *     the vault.
 *   - An attacker with XSS *can* decrypt live data while present on the
 *     page (inherent to any browser-resident key). Mitigations belong
 *     upstream: strict CSP, Trusted Types, SRI.
 *
 * Wire format compatibility: the KEK bytes are the raw bytes produced by
 * Atol's Argon2id derivation (32 bytes). The wrapped DEK the caller
 * passes to provision()/rehydrate() is the raw base64-decodable blob
 * straight from the `atol:wrapped_dek` ID token claim -- the vault does
 * not re-encode it.
 */

import { base64ToBytes } from "./base64url";

const DB_NAME = "atol-sdk";
const DB_VERSION = 1;
const STORE = "kek-vault";
const RECORD_KEY = "current";

/**
 * Stored shape. Note that `deviceKey` is a CryptoKey handle -- IndexedDB
 * is required to support structured-cloning CryptoKey, and every browser
 * that ships IndexedDB + WebCrypto in the last five years does.
 */
interface VaultRecord {
  deviceKey: CryptoKey;
  encryptedKEK: Uint8Array;
  iv: Uint8Array;
  version: number;
}

const CURRENT_VERSION = 1;

/** Bytes-in / bytes-out shape returned to callers. */
export interface UnwrappedDEK {
  dek: Uint8Array;
}

/**
 * Open (or upgrade) the SDK's IndexedDB database and return a request
 * handle. Factored so tests can stub the name via `indexedDB.deleteDatabase`.
 */
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("KEKVault: IndexedDB is not available"));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("KEKVault: open failed"));
  });
}

function readRecord(db: IDBDatabase): Promise<VaultRecord | null> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(RECORD_KEY);
    req.onsuccess = () => {
      const v = req.result as VaultRecord | undefined;
      resolve(v ?? null);
    };
    req.onerror = () => reject(req.error ?? new Error("KEKVault: read failed"));
  });
}

function writeRecord(db: IDBDatabase, rec: VaultRecord): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(rec, RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("KEKVault: write failed"));
    tx.onabort = () => reject(tx.error ?? new Error("KEKVault: write aborted"));
  });
}

function deleteRecord(db: IDBDatabase): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("KEKVault: delete failed"));
    tx.onabort = () => reject(tx.error ?? new Error("KEKVault: delete aborted"));
  });
}

function randomIV(): Uint8Array {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return iv;
}

function zero(bytes: Uint8Array): void {
  for (let i = 0; i < bytes.length; i++) bytes[i] = 0;
}

/**
 * Unwrap a DEK given raw KEK bytes. Mirrors the Atol server's
 * base64(nonce || ciphertext || tag) wrapping (AES-256-GCM, 12-byte
 * nonce, 16-byte tag, no AAD). Kept private to this module: the public
 * vault API takes `wrappedDEK` as a base64 string and returns raw DEK
 * bytes, hiding the KEK entirely.
 */
async function unwrapDEKWithKEK(
  kek: Uint8Array,
  wrappedDEKBase64: string,
): Promise<Uint8Array> {
  const wrapped = base64ToBytes(wrappedDEKBase64);
  if (wrapped.length < 12 + 16) {
    throw new Error("KEKVault: wrapped DEK shorter than nonce+tag");
  }
  const nonce = wrapped.slice(0, 12);
  const ciphertext = wrapped.slice(12);
  // Cast to ArrayBuffer for TS 5.7 BufferSource narrowing -- the backing
  // buffer is a real ArrayBuffer (base64ToBytes allocates Uint8Array).
  const key = await crypto.subtle.importKey(
    "raw",
    kek.buffer as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce.buffer as ArrayBuffer },
    key,
    ciphertext,
  );
  return new Uint8Array(plaintext);
}

/**
 * KEKVault is stateless by design -- construction is cheap and every
 * method opens its own IndexedDB transaction. That avoids holding long-
 * lived handles and plays cleanly with tab unload / page hide.
 */
export class KEKVault {
  /**
   * Stash the KEK under a fresh device key, then unwrap the DEK and
   * return its bytes. Call this on the first login-callback of a
   * session, when the KEK arrived in the URL fragment.
   *
   * Overwrites any existing vault record (key rotation, password change,
   * or user-switch on the same device all land here).
   *
   * `kekBytes` is zeroed after use. Callers should also drop their
   * local reference.
   */
  async provision(kekBytes: Uint8Array, wrappedDEKBase64: string): Promise<Uint8Array> {
    if (kekBytes.length === 0) {
      throw new Error("KEKVault.provision: kekBytes is empty");
    }
    if (wrappedDEKBase64 === "") {
      throw new Error("KEKVault.provision: wrappedDEK is empty");
    }

    // Generate a non-extractable AES-GCM device key. `encrypt` + `decrypt`
    // usages let us wrap and unwrap the KEK bytes locally; the key
    // itself never leaves WebCrypto's opaque handle.
    const deviceKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );

    const iv = randomIV();
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
        deviceKey,
        kekBytes.buffer as ArrayBuffer,
      ),
    );

    // Unwrap the DEK *before* persisting -- if the KEK is wrong the
    // wrapped-DEK auth tag fails here and we bail without leaving a
    // useless vault entry behind.
    const dek = await unwrapDEKWithKEK(kekBytes, wrappedDEKBase64);

    const db = await openDB();
    try {
      await writeRecord(db, {
        deviceKey,
        encryptedKEK: ciphertext,
        iv,
        version: CURRENT_VERSION,
      });
    } finally {
      db.close();
    }

    // Best-effort zero. Caller's reference is still live; we don't
    // control it. Document this in JSDoc above.
    zero(kekBytes);
    return dek;
  }

  /**
   * Rehydrate the DEK from the vault on silent-auth or page reload.
   * Returns null when there's no prior vault record -- caller falls
   * back to `signinRedirect` with `prompt=login` to repopulate.
   *
   * Returns null (rather than throwing) for the missing-state case
   * because it's a normal branch: new browser, cleared data, freshly
   * installed device. Actual errors (corrupted record, auth-tag fail
   * on the stored KEK) DO throw -- those indicate tampering or a bug
   * and the caller should escalate.
   */
  async rehydrate(wrappedDEKBase64: string): Promise<Uint8Array | null> {
    if (wrappedDEKBase64 === "") {
      throw new Error("KEKVault.rehydrate: wrappedDEK is empty");
    }
    const db = await openDB();
    let rec: VaultRecord | null;
    try {
      rec = await readRecord(db);
    } finally {
      db.close();
    }
    if (!rec) return null;
    if (rec.version !== CURRENT_VERSION) {
      // Future version skew: refuse to guess. Caller clears and
      // re-provisions on the next explicit login.
      return null;
    }

    const kekBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: rec.iv.buffer as ArrayBuffer },
      rec.deviceKey,
      rec.encryptedKEK.buffer as ArrayBuffer,
    );
    const kek = new Uint8Array(kekBuffer);
    try {
      return await unwrapDEKWithKEK(kek, wrappedDEKBase64);
    } finally {
      zero(kek);
    }
  }

  /**
   * Wipe the vault. Call from the logout path after `signoutRedirect`
   * so the next visit to this origin won't silently rehydrate the
   * previous user's DEK.
   *
   * Idempotent: a missing record is fine.
   */
  async clear(): Promise<void> {
    let db: IDBDatabase;
    try {
      db = await openDB();
    } catch {
      // IndexedDB unavailable -- nothing to clear.
      return;
    }
    try {
      await deleteRecord(db);
    } finally {
      db.close();
    }
  }

  /**
   * Non-destructive "does the vault have a record?" predicate. The
   * provider uses this to decide whether a silent refresh can succeed
   * or it needs to kick a `prompt=login`.
   */
  async hasRecord(): Promise<boolean> {
    let db: IDBDatabase;
    try {
      db = await openDB();
    } catch {
      return false;
    }
    try {
      const rec = await readRecord(db);
      return rec !== null && rec.version === CURRENT_VERSION;
    } finally {
      db.close();
    }
  }
}
