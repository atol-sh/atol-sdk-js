/**
 * Shorthand ambient declaration for the OPTIONAL peer dependency
 * `@atol-sh/fingerprint`. The package is not installed in this repo
 * (consumers opt in), so without this declaration the literal dynamic
 * `import('@atol-sh/fingerprint')` in the collector would fail
 * typechecking. The import site narrows the `any` this produces to the
 * structural `FingerprintModule` interface, which mirrors the published
 * package surface and the server identify contract.
 *
 * Not shipped: tsup's dts bundle only includes modules reachable from the
 * entry imports, and nothing imports from this file.
 */
declare module '@atol-sh/fingerprint'
