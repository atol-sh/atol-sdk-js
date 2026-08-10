# Release process

`@atol-sh/js` publishes to npm via **trusted publishing** (OIDC) in
[`.github/workflows/release.yml`](.github/workflows/release.yml): pushing a
`v*` tag builds and verifies the package in a job without OIDC authority,
creates one tarball with lifecycle scripts disabled, and hands it to a separate
publisher job. Before installing dependencies, the qualification job downloads
the npm 11.18.0 archive, verifies its official SHA-512 before extraction, and
invokes that CLI directly without a global install. The publisher job does not
check out the repository or install project dependencies and independently
repeats that exact verified npm bootstrap. It rehashes the received tarball,
uses `npm pack <tarball> --dry-run --ignore-scripts --json` to verify its exact package
identity, file count, sole `package.json`, empty bundled dependency set, and
public-only publish configuration, then publishes those exact bytes with
provenance. It boundedly waits for npm to report the same SHA-512 integrity.
There is no `NPM_TOKEN` in CI.

npm has no first-publish-via-OIDC yet ([npm/cli#8544](https://github.com/npm/cli/issues/8544)):
trusted publishing can only push versions to a package that **already
exists** on the registry. `@atol-sh/js` already exists, so its one-time
bootstrap is closed and no current or future version may use a local manual
publish path. Every release goes through the normal tag-push workflow.

The optional device subpath requires `@atol-sh/fingerprint` `^0.2.0`, and
`@atol-sh/react` depends on this package. For the staged browser SDK release,
publish and registry-verify fingerprint 0.2.0 first, this core 0.3.0 second,
and React 0.5.0 last.

## Trusted-publisher prerequisites

The repository must be public, and npm must bind `@atol-sh/js` to the exact
GitHub repository and `release.yml` workflow with no Environment name. Once
registered, npm accepts short-lived OIDC tokens minted by that workflow in
place of an `NPM_TOKEN`. Treat a missing or mismatched binding as a terminal
release configuration error; never fall back to a local publish or long-lived
token.

## Every release after the bootstrap

1. Update [`CHANGELOG.md`](./CHANGELOG.md): move the completed entries into the
   new version with the actual UTC release date, restore an empty
   `## [Unreleased]`, and commit it (`npm version` needs a clean tree).
2. Run `npm version <patch|minor|major>`. This bumps `package.json`, makes a
   commit, and creates a matching `vX.Y.Z` tag in one atomic step, so the
   version and the tag can never drift - the `release.yml` guard that checks
   tag == `package.json` version will always pass. Then push both together:
   `git push --follow-tags`.
3. `release.yml` runs on the tag push. Its unprivileged qualification job
   verifies the tag, typechecks, tests, builds, runs both package verifiers,
   and calls `npm pack --ignore-scripts --json` exactly once. It obtains npm
   11.18.0 from its official SHA-512-pinned registry archive before any npm
   command. The separate OIDC-authorized job receives only that tarball and
   independently verifies the same npm archive. It rechecks the tarball's
   name, version, package id, file count, sole `package.json`, empty bundled
   dependency set, exact `publishConfig: {"access":"public"}`, regular-file
   shape, and SHA-512. It publishes through the explicitly selected public
   registry and `latest` tag, then polls npm for at most two minutes and
   requires `dist.integrity` to match.
4. Confirm the version landed on [npmjs.com/package/@atol-sh/js](https://www.npmjs.com/package/@atol-sh/js)
   and that the GitHub Actions run shows a provenance attestation.
5. If `@atol-sh/react` needs this release, bump its `@atol-sh/js`
   dependency range only after this publish completes.

## Exact tag path for the already-staged 0.3.0

The repository already records package version 0.3.0 even though that version
has not been tagged or published. Do not run `npm version` for this release:
doing so would change the intended version. After all 0.3.0 source, tests,
packed documentation, and changelog content are final, create one frozen
release commit on `main`, run the full package gates against that commit, and
verify that npm still has no 0.3.0 and Git has no `v0.3.0` tag.
Fingerprint 0.2.0 must already be published and registry-integrity verified
before this tag is created.

This staged version includes ordinary browser authorization protocol v2. Its
release gates must cover the nested discovery endpoints, exact form and JSON
media types, browser exposure of `Atol-Browser-Authorization: v2`,
byte-identical pre-navigation cancellation, and proof-bound settlement.
Until those client/server wire checks pass against the frozen commit, 0.3.0
remains explicitly staged and unpublished.

From the clean checkout of that exact commit, bind the existing manifest
version to the tag without modifying package files:

```bash
version="$(node -p "require('./package.json').version")"
test "$version" = "0.3.0"
test "$(git branch --show-current)" = "main"
test -z "$(git status --porcelain)"
! git rev-parse --verify --quiet "refs/tags/v${version}"
git tag --annotate "v${version}" --message "@atol-sh/js ${version}" HEAD
git push --atomic origin \
  HEAD:refs/heads/main \
  "refs/tags/v${version}:refs/tags/v${version}"
```

The atomic push ensures the tag cannot reach the release workflow without the
frozen commit it names. The workflow then qualifies and publishes that exact
commit. Do not update React or any downstream lock until the workflow has
confirmed the registry `dist.integrity`.
