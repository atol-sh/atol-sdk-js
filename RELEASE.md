# Release process

`@atol-sh/js` publishes to npm via **trusted publishing** (OIDC) in
[`.github/workflows/release.yml`](.github/workflows/release.yml): pushing a
`v*` tag builds, verifies, and runs `npm publish --provenance` with no
`NPM_TOKEN` in CI.

npm has no first-publish-via-OIDC yet ([npm/cli#8544](https://github.com/npm/cli/issues/8544)):
trusted publishing can only push versions to a package that **already
exists** on the registry. The first release of a new package must be
published manually, once. Every release after that goes through the
normal tag-push workflow.

**`@atol-sh/react` depends on `@atol-sh/js`.** This package must be
published to npm *before* `@atol-sh/react`'s own release, or its install
will fail to resolve the dependency.

## One-time bootstrap (first publish only)

1. **Local packaging gate.** Before publishing anything, confirm the
   package is sound:

   ```bash
   npm run typecheck
   npm test
   npm run build
   npm run verify:pack   # publint + are-the-types-wrong (--pack . --profile node16)
   ```

   Fix any real `publint` error or `attw` problem (FalseCJS, FalseESM,
   no-types, resolution-failed) before proceeding. Warnings that are
   expected for this package's shape (e.g. the ignored `node10` profile
   resolution failure on the `./device` subpath) need no fix.

2. **Manual first publish.** From a clean checkout on `main`, logged into
   an npm account with publish rights on the `@atol-sh` org:

   ```bash
   npm publish --access public
   ```

   This creates the package on the registry at the version currently in
   `package.json`. This is the only time `@atol-sh/js` is published from a
   local machine -- every subsequent release goes through CI.

3. **Register trusted publishing on npmjs.com.** On the package's
   Settings page, add a trusted publisher:
   - Provider: GitHub Actions
   - Organization: `atol-sh`
   - Repository: `atol-sdk-js`
   - Workflow filename: `release.yml`
   - Environment: (none)

   Once registered, npm accepts short-lived OIDC tokens minted by that
   exact workflow in place of an `NPM_TOKEN`.

4. **Make the repository public first.** `atol-sdk-js` is private for now.
   `npm publish --provenance` and trusted publishing's automatic provenance
   both require a public repo — a provenance publish from a private repo
   errors. Flip the repo to public before the first tag-driven release
   (ideally before step 2, so even the bootstrap version can carry
   provenance). The main `atol-sh/atol` repo stays closed-source; only the
   SDK repos go public.

## Every release after the bootstrap

1. Update [`CHANGELOG.md`](./CHANGELOG.md): rename `## [Unreleased]` to the
   new version with today's date, and commit it (`npm version` needs a clean
   tree).
2. Run `npm version <patch|minor|major>`. This bumps `package.json`, makes a
   commit, and creates a matching `vX.Y.Z` tag in one atomic step, so the
   version and the tag can never drift — the `release.yml` guard that checks
   tag == `package.json` version will always pass. Then push both together:
   `git push --follow-tags`.
3. `release.yml` runs on the tag push: verifies the tag matches
   `package.json`'s version, typechecks, tests, builds, runs `publint`,
   then `npm publish --provenance --access public` using the registered
   trusted publisher -- no secrets involved.
4. Confirm the version landed on [npmjs.com/package/@atol-sh/js](https://www.npmjs.com/package/@atol-sh/js)
   and that the GitHub Actions run shows a provenance attestation.
5. If `@atol-sh/react` needs this release, bump its `@atol-sh/js`
   dependency range only after this publish completes.
