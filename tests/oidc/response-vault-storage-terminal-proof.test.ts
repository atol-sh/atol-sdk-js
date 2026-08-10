/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it } from 'vitest'
import { bytesToBase64Url } from '../../src/crypto/base64url'
import { validResponseVaultTerminalProof } from '../../src/oidc/response-vault-storage'
import {
  BOOTSTRAP_TERMINAL_PROOF,
  TERMINAL_PROOF,
} from './response-vault-regression-helpers'

describe('response-vault terminal proof validation', () => {
  it('accepts only canonical 58-byte raw-base64url proofs', () => {
    expect(validResponseVaultTerminalProof(
      BOOTSTRAP_TERMINAL_PROOF,
    )).toBe(true)
    expect(validResponseVaultTerminalProof(TERMINAL_PROOF)).toBe(true)

    const standardAlphabet = bytesToBase64Url(
      new Uint8Array(58).fill(0xfb),
    ).replace(/-/g, '+').replace(/_/g, '/')
    expect(standardAlphabet).toHaveLength(78)
    expect(validResponseVaultTerminalProof(standardAlphabet)).toBe(false)
    expect(
      validResponseVaultTerminalProof(TERMINAL_PROOF.slice(0, -1)),
    ).toBe(false)
    expect(
      validResponseVaultTerminalProof(`${TERMINAL_PROOF}=`),
    ).toBe(false)
    expect(
      validResponseVaultTerminalProof(
        `${TERMINAL_PROOF.slice(0, -1)}h`,
      ),
    ).toBe(false)
    expect(validResponseVaultTerminalProof('*'.repeat(78))).toBe(false)
    expect(validResponseVaultTerminalProof(undefined)).toBe(false)
  })
})
