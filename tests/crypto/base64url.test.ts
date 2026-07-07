/**
 * base64ToBytes is the decode trust boundary for KEK/wrapped-DEK/DPoP
 * inputs. It must round-trip valid base64/base64url (padded or not) and
 * reject malformed input deterministically rather than leaning on lenient
 * browser atob behavior.
 */
import { describe, expect, it } from 'vitest'
import {
  base64ToBytes,
  bytesToBase64Url,
  stringToBase64Url,
} from '../../src/crypto/base64url'

describe('base64ToBytes', () => {
  it('round-trips unpadded base64url', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 255])
    const encoded = bytesToBase64Url(bytes)
    expect(Array.from(base64ToBytes(encoded))).toEqual(Array.from(bytes))
  })

  it('accepts standard base64 with padding', () => {
    // "Man" -> "TWFu", "Ma" -> "TWE="
    expect(Array.from(base64ToBytes('TWE='))).toEqual([0x4d, 0x61])
  })

  it('accepts the URL-safe alphabet', () => {
    // 0xff,0xff -> standard "//8=", url-safe "__8"
    expect(Array.from(base64ToBytes('__8'))).toEqual([0xff, 0xff])
  })

  it('decodes empty string to an empty array', () => {
    expect(Array.from(base64ToBytes(''))).toEqual([])
  })

  it('rejects non-base64 characters', () => {
    expect(() => base64ToBytes('abc$def')).toThrow(/non-base64/)
  })

  it('rejects embedded whitespace (no silent stripping)', () => {
    expect(() => base64ToBytes('TW Fu')).toThrow(/non-base64/)
  })

  it('rejects a null byte (%00) in the input', () => {
    expect(() => base64ToBytes('TW\x00Fu')).toThrow(/non-base64/)
  })

  it('rejects an impossible length (len % 4 === 1)', () => {
    expect(() => base64ToBytes('TWFuX')).toThrow(/invalid base64 length/)
  })
})

describe('bytesToBase64Url', () => {
  it('produces unpadded url-safe output (no + / =)', () => {
    // 0xfb 0xff -> standard "+/8=" -> url-safe "-_8"
    const out = bytesToBase64Url(new Uint8Array([0xfb, 0xff]))
    expect(out).toBe('-_8')
    expect(out).not.toMatch(/[+/=]/)
  })

  it('round-trips arbitrary byte ranges', () => {
    for (let len = 0; len < 40; len++) {
      const bytes = new Uint8Array(len)
      for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) & 0xff
      expect(Array.from(base64ToBytes(bytesToBase64Url(bytes)))).toEqual(
        Array.from(bytes),
      )
    }
  })
})

describe('stringToBase64Url', () => {
  it('encodes ASCII round-trip', () => {
    const s = 'hello.world'
    const enc = stringToBase64Url(s)
    expect(new TextDecoder().decode(base64ToBytes(enc))).toBe(s)
  })

  it('encodes multi-byte unicode (UTF-8) correctly', () => {
    const s = 'héllo — 世界 🚀'
    const enc = stringToBase64Url(s)
    expect(new TextDecoder().decode(base64ToBytes(enc))).toBe(s)
    expect(enc).not.toMatch(/[+/=]/)
  })

  it('encodes the empty string to the empty string', () => {
    expect(stringToBase64Url('')).toBe('')
  })
})
