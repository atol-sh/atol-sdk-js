/**
 * Shared base64 / base64url helpers.
 *
 * Single source of truth for byte <-> base64 conversion across the SDK
 * (encryption, KEK vault, PKCE, DPoP). The decoder accepts both the
 * standard "+/" alphabet and the URL-safe "-_" alphabet, with or without
 * padding, because the Atol server emits unpadded base64url while older
 * tooling may emit padded standard base64.
 */

/** Encode raw bytes as unpadded base64url. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Encode a UTF-8 string as unpadded base64url. */
export function stringToBase64Url(input: string): string {
  return bytesToBase64Url(new TextEncoder().encode(input))
}

/**
 * Decode a base64 or base64url string (padded or not) into raw bytes.
 *
 * This is the trust boundary for attacker-influenceable inputs (the KEK
 * from the URL fragment, the wrapped DEK from a token claim, DPoP
 * signatures). Validate the alphabet and reject impossible lengths
 * explicitly so behavior is deterministic across engines instead of
 * relying on the historically-lenient browser `atob` (which silently
 * strips whitespace and tolerates trailing bits on some implementations).
 */
export function base64ToBytes(b64: string): Uint8Array {
  // Normalize to the standard alphabet and drop any trailing padding so we
  // can validate the payload alphabet and re-pad canonically.
  const std = b64.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '')
  if (!/^[A-Za-z0-9+/]*$/.test(std)) {
    throw new Error('base64ToBytes: input contains non-base64 characters')
  }
  // length % 4 === 1 is not a producible base64 length -- reject rather
  // than let re-padding mask a corrupted value.
  if (std.length % 4 === 1) {
    throw new Error('base64ToBytes: invalid base64 length')
  }
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
