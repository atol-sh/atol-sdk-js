import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      // Optional peer dependency, not installed in this repo. The device
      // subpath dynamic-imports it; tests resolve it to a controllable stub.
      '@atol-sh/fingerprint': fileURLToPath(
        new URL('./tests/stubs/fingerprint.ts', import.meta.url),
      ),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['tests/**/*.test.{ts,tsx}'],
    setupFiles: ['tests/setup.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      // Ambient-only / re-export surfaces with no runtime to exercise.
      exclude: [
        'src/index.ts',
        'src/device.ts',
        'src/**/*.d.ts',
      ],
      reporter: ['text', 'html', 'json-summary'],
      // Coverage is a HARD CI GATE. The security-critical modules
      // (crypto, dpop, verify, oidc/pkce, permissions, cross-tab
      // broadcast) carry the platform's browser-side auth guarantees, so
      // they are held to a high per-file floor. CI fails below any of
      // these numbers.
      thresholds: {
        // Global floor across the whole core.
        lines: 90,
        branches: 88,
        functions: 90,
        statements: 90,
        // Per-file floors for the security-critical surface.
        'src/crypto/base64url.ts': {
          lines: 100,
          branches: 95,
          functions: 100,
          statements: 100,
        },
        'src/crypto/encryption.ts': {
          lines: 95,
          branches: 90,
          functions: 100,
          statements: 95,
        },
        'src/crypto/kek-vault.ts': {
          lines: 95,
          branches: 95,
          // The IndexedDB request `onerror`/`onabort` reject callbacks are
          // defensive closures that never fire under fake-indexeddb's happy
          // path; v8 counts each as an uncovered function. Lines/branches/
          // statements (the meaningful security surface) stay at 95+.
          functions: 70,
          statements: 95,
        },
        'src/dpop/dpop.ts': {
          lines: 95,
          branches: 90,
          functions: 100,
          statements: 95,
        },
        'src/verify/verify.ts': {
          lines: 95,
          branches: 90,
          functions: 100,
          statements: 95,
        },
        'src/oidc/silent-renew.ts': {
          lines: 90,
          branches: 88,
          functions: 90,
          statements: 90,
        },
        'src/oidc/token-recovery.ts': {
          lines: 100,
          branches: 95,
          functions: 100,
          statements: 100,
        },
        'src/oidc/oidc.ts': {
          lines: 95,
          branches: 88,
          functions: 100,
          statements: 95,
        },
        'src/token/token-broadcast.ts': {
          lines: 95,
          branches: 90,
          functions: 90,
          statements: 95,
        },
        'src/permissions/permissions.ts': {
          lines: 100,
          branches: 95,
          functions: 100,
          statements: 100,
        },
      },
    },
  },
})
