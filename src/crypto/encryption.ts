/**
 * Zero-knowledge encryption primitives.
 *
 * The KEK (Key Encryption Key) is delivered via URL fragment by the Atol
 * authorize endpoint. The wrapped DEK (Data Encryption Key) arrives as
 * an ID token claim. The client unwraps the DEK locally and hands the
 * KEK to the vault (see `./kek-vault.ts`) so silent-auth refreshes can
 * rehydrate the DEK without a password prompt.
 *
 * This module stays intentionally small: fragment parsing, byte
 * conversion helpers, and the one-shot unwrap. DEK persistence is the
 * vault's job, not this module's.
 */

import { base64ToBytes } from './base64url'

/**
 * Extract the KEK from the URL fragment and clean up immediately.
 * The fragment is set by the Atol authorize endpoint: `#atol_enc_key=base64(kek)`.
 * Returns null when not present.
 */
export function extractKEKFromFragment(): string | null {
  const hash = window.location.hash
  if (!hash) return null

  const params = new URLSearchParams(hash.substring(1))
  const kek = params.get('atol_enc_key')

  // Treat an empty value (`#atol_enc_key=`) as "not present" so callers
  // can rely on the non-null return shape. Without this guard callers
  // would later crash at atob/base64 decode.
  if (!kek) return null

  params.delete('atol_enc_key')
  const remaining = params.toString()
  const newHash = remaining ? '#' + remaining : ''
  window.history.replaceState(
    {},
    document.title,
    window.location.pathname + window.location.search + newHash,
  )

  return kek
}

/**
 * Decode a base64 / base64url string into raw bytes. Accepts either
 * the "+/" standard alphabet or the "-_" URL-safe alphabet, with or
 * without padding. The Atol authorize endpoint emits base64url without
 * padding; older servers may emit padded base64.
 *
 * Thin alias over the shared decoder in `./base64url` -- kept exported
 * under this name because it is part of the public API.
 */
export function kekBase64ToBytes(b64: string): Uint8Array {
  return base64ToBytes(b64)
}

/**
 * Unwrap a DEK using the KEK via AES-256-GCM (Web Crypto API). The
 * `wrappedDEK` format is `base64(nonce12bytes || ciphertext || tag)`,
 * matching the wire format the Atol authorize endpoint emits.
 *
 * Kept as a public utility so callers that prefer to own DEK lifetime
 * themselves (e.g. tests, or frontends that intentionally avoid
 * persisting the DEK across reloads) can unwrap without pulling in the
 * vault machinery.
 */
export async function unwrapDEK(
  kekBase64: string,
  wrappedDEKBase64: string,
): Promise<Uint8Array> {
  const kek = kekBase64ToBytes(kekBase64)
  const wrapped = kekBase64ToBytes(wrappedDEKBase64)

  // Validate sizes before importKey so a corrupted/attacker-supplied value
  // fails with an actionable message instead of an opaque WebCrypto
  // DataError. AES-GCM keys are 16/24/32 bytes; the wrapped blob is
  // nonce(12) || ciphertext || tag(16).
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error(`unwrapDEK: KEK must be 16/24/32 bytes, got ${kek.length}`)
  }
  if (wrapped.length < 12 + 16) {
    throw new Error('unwrapDEK: wrapped DEK shorter than nonce+tag')
  }

  const nonce = wrapped.slice(0, 12) // AES-GCM standard nonce size
  const ciphertext = wrapped.slice(12)

  // Cast to ArrayBuffer for TS 5.7 BufferSource narrowing -- the backing
  // buffer is a real ArrayBuffer (kekBase64ToBytes allocates fresh).
  const key = await crypto.subtle.importKey(
    'raw',
    kek.buffer as ArrayBuffer,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce.buffer as ArrayBuffer },
    key,
    ciphertext,
  )

  return new Uint8Array(plaintext)
}
