# Security Policy

`@atol-sh/js` is a browser security core (OIDC + PKCE, DPoP, token storage,
ID token verification). We treat vulnerability reports in this package as a
priority.

## Supported Versions

While the package is pre-1.0, only the latest published minor version
receives security fixes. Once 1.0 ships, this table will track supported
major versions.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for a suspected security
vulnerability.** Public issues are visible to everyone, including
potential attackers, before a fix is available.

Report privately using one of these channels:

1. **GitHub private security advisory** (preferred): open one at
   [github.com/atol-sh/atol-sdk-js/security/advisories/new](https://github.com/atol-sh/atol-sdk-js/security/advisories/new).
   This lets us discuss and fix the issue with you in a private space
   before disclosure.
2. **Email**: security@atol.sh. If you'd like to encrypt your report, ask
   for a PGP key in your initial message.

### What to include

To help us triage and reproduce quickly, please include:

- A description of the vulnerability and its impact (e.g. token leakage,
  session takeover, signature bypass, DPoP proof forgery).
- Steps to reproduce, or a minimal proof-of-concept.
- The affected version(s) of `@atol-sh/js`.
- Any relevant browser, runtime, or configuration details.
- Whether you believe the issue also affects framework bindings built on
  this core (e.g. `@atol-sh/react`).

### What to expect

- We will acknowledge your report as soon as we reasonably can.
- We will investigate and keep you updated as we make progress.
- We aim to agree on a disclosure timeline with you that gives us time to
  develop, test, and release a fix before public disclosure. We follow
  coordinated disclosure norms and ask that you do not disclose publicly
  until a fix is available or an agreed timeline has elapsed.
- Once a fix is released, we will credit reporters who wish to be credited
  in the release notes, unless you prefer to remain anonymous.

We do not currently operate a paid bug bounty program, but we sincerely
appreciate responsible disclosure and will credit researchers who help
keep Atol's users safe.

## Scope

This policy covers the `@atol-sh/js` package itself: its source in this
repository and the artifacts published to npm as `@atol-sh/js`. Issues in
third-party dependencies should generally be reported upstream as well;
let us know if a dependency vulnerability affects this package so we can
track and update it.
