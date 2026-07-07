# @atol-sh/js

Framework-agnostic browser security core for Atol: OIDC (Authorization
Code + PKCE), DPoP sender-constrained tokens (RFC 9449), silent renewal,
cross-tab coordination, permission loading, and WebCrypto-backed
primitives. Published to npm as `@atol-sh/js`, Apache-2.0 licensed.

The keystone export is `createAtolBrowserAuth` (`src/client/browser-auth.ts`).
Framework bindings such as `@atol-sh/react` are thin wrappers over it.

## IP / OSS safety

**This repository is public.** It must never contain:

- References to, or details of, any closed-source/internal system.
- Local filesystem paths (e.g. home directory paths, machine-specific
  paths).
- Secrets, credentials, API keys, or tokens of any kind.
- Internal architecture, infra, or roadmap details that aren't meant for
  a public audience.

Use generic, public-safe examples in docs and comments: placeholder
issuers like `https://id.atol.sh` or `https://id.example.com`, example.com
redirect URIs, and so on. Keep all documentation and code comments ASCII
only (no em dashes, no smart quotes, no Unicode bullets).

## Layout

```
src/
  client/        createAtolBrowserAuth (the keystone)
  oidc/          OIDC/PKCE, silent renew, cross-tab lock, token recovery
  dpop/          DPoP (RFC 9449) key manager and proof signing
  verify/        ID token verification against the issuer's JWKS
  token/         Cross-tab token broadcast
  permissions/   Permission loading
  claims/        JWT claim parsing and shared types
  crypto/        Zero-knowledge encryption primitives (KEK vault, base64url)
  device/        Device intelligence collector (optional, see below)
  index.ts       Public entry point (barrel export)
  device.ts      Optional `@atol-sh/js/device` subpath entry point
tests/           Mirrors src/ 1:1; vitest + jsdom
```

The `./device` subpath is split out of the main entry point so consumers
who don't use device intelligence never pull the optional
`@atol-sh/fingerprint` peer dependency into their bundle.

## Commands

```bash
npm ci                 # install exactly from package-lock.json
npm run build          # tsup -> dist/ (ESM + CJS + types)
npm test               # vitest run
npm run test:coverage  # vitest run --coverage (enforces the coverage gate)
npm run typecheck      # tsc --noEmit
```

## Coverage gate

Coverage thresholds in `vitest.config.ts` are a **hard CI gate**: a global
floor across the package, plus stricter per-file floors on the
security-critical modules (`crypto/`, `dpop/`, `verify/`, `oidc/`,
`token/`, `permissions/`). A change that drops any threshold fails CI.
Security-critical modules should get adversarial/negative tests, not just
happy-path coverage: expired or malformed tokens, wrong issuer/audience,
tampered DPoP proofs, missing WebCrypto, forged cross-tab messages.

See `CONTRIBUTING.md` for the full contribution workflow and
`SECURITY.md` for how to report a vulnerability privately.
