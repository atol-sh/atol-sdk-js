import { defineConfig } from 'tsup'

export default defineConfig({
  // Two entry points: the core barrel and the optional device subpath.
  // `./device` is split out so consumers that never touch device
  // intelligence do not pull @atol-sh/fingerprint into their bundle.
  entry: ['src/index.ts', 'src/device.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  // Source maps ship intentionally: this is open source, and they make
  // debugging the SDK inside a consuming app possible.
  sourcemap: true,
  clean: true,
  // @atol-sh/fingerprint is an optional peer dependency, loaded via a
  // dynamic import only from the device subpath. It must never be bundled.
  // (oidc-client-ts / jose are also externalized automatically as declared
  // dependencies.)
  external: ['@atol-sh/fingerprint'],
  treeshake: true,
})
