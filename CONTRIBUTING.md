# Contributing to @atol-sh/js

Thanks for considering a contribution. This package is the framework-agnostic
browser security core for Atol (OIDC + PKCE, DPoP, silent renew, permissions,
WebCrypto), so changes here affect every framework binding built on top of
it. Please read this guide before opening a PR.

## Dev setup

Requires Node.js 18+.

```bash
git clone https://github.com/atol-sh/atol-sdk-js.git
cd atol-sdk-js
npm ci
```

`npm ci` installs from `package-lock.json` exactly; use it instead of
`npm install` for a reproducible environment.

## Scripts

| Script | Purpose |
|---|---|
| `npm run build` | Build ESM + CJS output (tsup) into `dist/`. |
| `npm run dev` | Build in watch mode. |
| `npm test` | Run the unit test suite once (vitest). |
| `npm run test:watch` | Run tests in watch mode. |
| `npm run test:coverage` | Run tests with coverage, enforcing the coverage gate below. |
| `npm run typecheck` | Type-check the whole project with `tsc --noEmit`. |
| `npm run clean` | Remove `dist/`. |

Run `npm run typecheck` and `npm test` before opening a PR; CI runs both,
plus `test:coverage` and a production build, on every push and pull request.

## The coverage gate

Coverage is a **hard CI gate**, not an informational report. Thresholds are
defined in `vitest.config.ts`: a global floor across the whole package,
plus stricter per-file floors on the security-critical modules (DPoP, ID
token verification, OIDC/PKCE, the KEK vault and other crypto helpers,
cross-tab token broadcast, permissions). A pull request that drops any of
these thresholds fails CI and will not be merged.

If you add a new module under one of the security-critical directories
(`src/crypto/`, `src/dpop/`, `src/verify/`, `src/oidc/`,
`src/token/`, `src/permissions/`), expect to add a corresponding
per-file threshold entry in `vitest.config.ts` once the module has full
test coverage.

## Security-critical modules need adversarial tests

For `src/dpop/`, `src/verify/`, `src/oidc/`, and `src/crypto/`, tests
should not only cover the happy path. Add negative and adversarial cases:
expired or malformed tokens, wrong issuer/audience, replayed or tampered
DPoP proofs, missing or corrupt WebCrypto support, forged cross-tab
broadcast messages, and similar failure modes. A change to one of these
modules without a test that tries to break it will likely be asked to add
one in review.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/) for
commit messages, e.g.:

```
feat(dpop): support server-issued nonce retry
fix(oidc): handle missing refresh_token on silent renew
docs(readme): clarify DPoP fallback behavior
test(verify): add expired-JWKS-cache adversarial case
```

This keeps history scannable and lines up with the `CHANGELOG.md`
[Keep a Changelog](https://keepachangelog.com/) format.

## Pull request flow

1. Fork the repository and create a branch off `main`.
2. Make your change. Keep it focused; unrelated fixes belong in a separate PR.
3. Add or update tests. New modules need tests; behavior changes need
   updated assertions.
4. Run `npm run typecheck && npm run test:coverage && npm run build` locally.
5. Update `CHANGELOG.md` under an `[Unreleased]` section if the change is
   user-visible.
6. Open a PR against `main` with a clear description of the change and why
   it's needed. Link any related issue.
7. A maintainer will review; CI (typecheck, coverage-gated tests, build,
   `npm audit`) must be green before merge.

## Developer Certificate of Origin (DCO)

By submitting a pull request, you certify that you wrote the contribution
yourself or otherwise have the right to submit it under the project's
Apache-2.0 license, per the
[Developer Certificate of Origin](https://developercertificate.org/).
Please sign off your commits:

```bash
git commit -s -m "feat(dpop): support server-issued nonce retry"
```

This adds a `Signed-off-by` trailer to the commit message.

## Reporting security issues

Do not open a public issue for a suspected vulnerability. See
[SECURITY.md](./SECURITY.md) for how to report privately.
