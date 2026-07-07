/**
 * Test stub for the optional peer dependency `@atol-sh/fingerprint`.
 * Wired in via the vitest alias (see vitest.config.ts) so the device
 * collector's dynamic import resolves in tests. Tests drive behavior
 * through `loadMock`.
 */
import { vi } from 'vitest'

export const loadMock = vi.fn()

export class AtolFingerprint {
  static load = loadMock
}
