/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import { bytesToBase64Url } from '../../src/crypto/base64url'
import {
  canonicalOrdinaryAuthorizationBinding,
  parseOrdinaryAuthorizationIntent,
  serializedOrdinaryAuthorizationIntent,
  validCanonicalAttemptCapability,
  type OrdinaryAuthorizationBinding,
  type OrdinaryAuthorizationRecord,
} from '../../src/oidc/ordinary-authorization-model'
import {
  ordinaryAuthorizationAttemptCapabilityDeadline,
  ordinaryAuthorizationAttemptChallenge,
  ordinaryAuthorizationDiscoveryContract,
  ordinaryAuthorizationNavigationURL,
  readBoundedOrdinaryAuthorizationResponse,
  validOrdinaryAuthorizationTerminalProof,
} from '../../src/oidc/ordinary-authorization-protocol'
import { canonicalOrdinaryAuthorizationForm } from '../../src/oidc/ordinary-authorization-validation'

const OPAQUE = 'A'.repeat(43)
const REQUEST_URI = `urn:ietf:params:oauth:request_uri:${OPAQUE}`
const STATE = 'a'.repeat(32)
const NONCE = 'b'.repeat(64)
const CHALLENGE = bytesToBase64Url(new Uint8Array(32).fill(7))

const BINDING: OrdinaryAuthorizationBinding = {
  issuer: 'https://auth.atol.test',
  clientId: 'atol_kid_test',
  redirectUri: 'https://app.test/cb',
  scope: 'openid profile email',
}

function terminalProof(kind: number, deadlineMs: number): string {
  const raw = new Uint8Array(58)
  raw[0] = 1
  raw[1] = kind
  let deadline = BigInt(deadlineMs) * 1_000_000n
  for (let index = 25; index >= 18; index--) {
    raw[index] = Number(deadline & 0xffn)
    deadline >>= 8n
  }
  return bytesToBase64Url(raw)
}

function generatedAuthorizationURL(): string {
  const parameters = new URLSearchParams({
    response_type: 'code',
    client_id: BINDING.clientId,
    redirect_uri: BINDING.redirectUri,
    scope: BINDING.scope,
    state: STATE,
    nonce: NONCE,
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
  })
  return `${BINDING.issuer}/auth/authorize?${parameters}`
}

function ordinaryRecord(
  overrides: Partial<OrdinaryAuthorizationRecord> = {},
): OrdinaryAuthorizationRecord {
  const createdAt = Date.UTC(2029, 0, 1)
  const record = {
    version: 2,
    revision: 1,
    slotKey: 'ordinary-authorization-test-slot',
    stateId: STATE,
    ...BINDING,
    credentialGeneration: {
      logout: 'L'.repeat(43),
      tabOwner: 'T'.repeat(43),
    },
    intent: serializedOrdinaryAuthorizationIntent({
      dpopEnabled: false,
      dpopRequired: false,
    }),
    stateStorage: '{}',
    stateCreatedAt: createdAt,
    form: new URL(generatedAuthorizationURL()).searchParams.toString(),
    createdAt,
    provisionalExpiresAt: createdAt + 1_500_000,
    attemptExpiresAtMs: null,
    pushedAuthorizationRequestEndpoint: `${BINDING.issuer}/auth/par`,
    preNavigationCancellationEndpoint:
      `${BINDING.issuer}/auth/par/pre-navigation-cancellation`,
    settlementEndpoint: `${BINDING.issuer}/auth/par/settlement`,
    authorizationEndpoint: `${BINDING.issuer}/auth/authorize`,
    protocolVersion: 2,
    ceremonyLifetimeSeconds: 900,
    authorizationCodeLifetimeSeconds: 600,
    dpopJkt: null,
    keys: null,
    cancellationSecret: 'C'.repeat(43),
    parPhase: 'prepared',
    requestUri: null,
    terminalProof: null,
    rootExpiresAt: null,
    rootExpiresAtMs: null,
    custodyExpiresAtMs: null,
    callbackClaimId: null,
    callbackClaimExpiresAtMs: null,
    callbackCode: null,
    callbackCodeHash: null,
    compensationRequired: false,
    rejectionRequired: false,
    cleanupStarted: false,
  } satisfies OrdinaryAuthorizationRecord
  return { ...record, ...overrides }
}

describe('ordinary authorization canonical input boundaries', () => {
  it('rejects malformed capabilities before treating them as authority', () => {
    expect(validCanonicalAttemptCapability(undefined)).toBe(false)
    expect(validCanonicalAttemptCapability('!'.repeat(78))).toBe(false)
    expect(() =>
      ordinaryAuthorizationAttemptCapabilityDeadline(
        terminalProof(2, 0),
      ),
    ).toThrow(/attempt capability is invalid/)
  })

  it('accepts only trustworthy loopback or HTTPS bindings', () => {
    expect(() =>
      canonicalOrdinaryAuthorizationBinding({
        ...BINDING,
        issuer: 'not a URL',
      }),
    ).toThrow(/issuer is invalid/)
    expect(() =>
      canonicalOrdinaryAuthorizationBinding({
        ...BINDING,
        issuer: 'ftp://auth.atol.test',
      }),
    ).toThrow(/issuer is invalid/)
    expect(
      canonicalOrdinaryAuthorizationBinding({
        ...BINDING,
        issuer: 'http://localhost',
        redirectUri: 'http://localhost/cb',
      }).issuer,
    ).toBe('http://localhost')
    expect(
      canonicalOrdinaryAuthorizationBinding({
        ...BINDING,
        issuer: 'http://127.0.0.2',
        redirectUri: 'http://127.0.0.2/cb',
      }).issuer,
    ).toBe('http://127.0.0.2')
    expect(() =>
      canonicalOrdinaryAuthorizationBinding({
        ...BINDING,
        issuer: 'http://192.0.2.1',
      }),
    ).toThrow(/issuer is invalid/)
    expect(() =>
      canonicalOrdinaryAuthorizationBinding({
        ...BINDING,
        redirectUri: 'not a URL',
      }),
    ).toThrow(/redirect URI is invalid/)
    expect(() =>
      canonicalOrdinaryAuthorizationBinding({
        ...BINDING,
        scope: 'profile email',
      }),
    ).toThrow(/binding is invalid/)
  })

  it('rejects malformed and non-canonical serialized intent', () => {
    expect(() =>
      serializedOrdinaryAuthorizationIntent({
        dpopEnabled: false,
        dpopRequired: true,
      }),
    ).toThrow(/intent is invalid/)
    expect(
      serializedOrdinaryAuthorizationIntent({
        dpopEnabled: false,
        dpopRequired: false,
      }),
    ).toContain('"extra_query":[]')
    expect(() => parseOrdinaryAuthorizationIntent('{}')).toThrow(
      /stored intent is invalid/,
    )

    const fields = {
      response_mode: null,
      prompt: null,
      max_age: null,
      acr_values: null,
      return_to: null,
      extra_query: [
        ['audience', 'one'],
        ['audience', 'two'],
      ],
      dpop_enabled: false,
      dpop_required: false,
    }
    expect(() =>
      parseOrdinaryAuthorizationIntent(JSON.stringify(fields)),
    ).toThrow(/stored intent is invalid/)

    const nonCanonical = JSON.stringify({
      dpop_required: false,
      dpop_enabled: false,
      extra_query: [],
      return_to: null,
      acr_values: null,
      max_age: null,
      prompt: null,
      response_mode: null,
    })
    expect(() =>
      parseOrdinaryAuthorizationIntent(nonCanonical),
    ).toThrow(/stored intent is invalid/)
  })

  it('rejects generated authorization URLs outside their exact binding', () => {
    expect(() =>
      canonicalOrdinaryAuthorizationForm(
        generatedAuthorizationURL().replace(
          BINDING.issuer,
          'https://attacker.test',
        ),
        BINDING,
        { stateId: STATE, nonce: NONCE, codeChallenge: CHALLENGE },
      ),
    ).toThrow(/generated endpoint is invalid/)

    const duplicate = new URL(generatedAuthorizationURL())
    duplicate.searchParams.append('state', STATE)
    expect(() =>
      canonicalOrdinaryAuthorizationForm(duplicate.href, BINDING, {
        stateId: STATE,
        nonce: NONCE,
        codeChallenge: CHALLENGE,
      }),
    ).toThrow(/generated form is invalid/)

    expect(() =>
      canonicalOrdinaryAuthorizationForm(
        generatedAuthorizationURL(),
        BINDING,
        {
          stateId: 'c'.repeat(32),
          nonce: NONCE,
          codeChallenge: CHALLENGE,
        },
      ),
    ).toThrow(/generated form binding is invalid/)
  })
})

describe('ordinary authorization protocol boundaries', () => {
  it('rejects discovery substitution and malformed browser metadata', () => {
    expect(() =>
      ordinaryAuthorizationDiscoveryContract(
        { issuer: 'https://attacker.test' },
        BINDING,
      ),
    ).toThrow(/discovered issuer is invalid/)
    expect(() =>
      ordinaryAuthorizationDiscoveryContract(
        {
          issuer: BINDING.issuer,
          require_pushed_authorization_requests: true,
          atol_browser_authorization: [],
        },
        BINDING,
      ),
    ).toThrow(/discovery contract is invalid/)
  })

  it('requires canonical terminal proof kind and deadline binding', () => {
    const deadline = Date.UTC(2030, 0, 1)
    const root = new Date(deadline).toISOString()
    const proof = terminalProof(1, deadline)
    expect(
      validOrdinaryAuthorizationTerminalProof(
        proof,
        new Date(deadline + 1_000).toISOString(),
      ),
    ).toBe(false)
    expect(
      validOrdinaryAuthorizationTerminalProof(proof, root),
    ).toBe(true)
    expect(
      validOrdinaryAuthorizationTerminalProof(
        terminalProof(2, deadline),
        root,
      ),
    ).toBe(false)
    expect(
      validOrdinaryAuthorizationTerminalProof('!'.repeat(78), root),
    ).toBe(false)
  })

  it('rejects malformed, mismatched, and overflowing attempt challenges', () => {
    const started = Date.UTC(2030, 0, 1)
    const deadline = started + 800_000
    const capability = terminalProof(2, deadline)
    const valid = {
      error: 'attempt_capability_required',
      attempt_capability: capability,
      expires_in: 800,
      attempt_expires_at: new Date(deadline).toISOString(),
    }
    expect(() =>
      ordinaryAuthorizationAttemptChallenge(
        ordinaryRecord(),
        JSON.stringify({ ...valid, error: 'invalid_request' }),
        started,
      ),
    ).toThrow(/attempt challenge is invalid/)
    expect(() =>
      ordinaryAuthorizationAttemptChallenge(
        ordinaryRecord(),
        JSON.stringify(valid),
        -1,
      ),
    ).toThrow(/attempt deadline is invalid/)
    expect(() =>
      ordinaryAuthorizationAttemptChallenge(
        ordinaryRecord(),
        JSON.stringify({
          ...valid,
          attempt_expires_at: new Date(deadline + 1_000).toISOString(),
        }),
        started,
      ),
    ).toThrow(/attempt capability is invalid/)

    const maximum = Number.MAX_SAFE_INTEGER
    const maximumCapability = terminalProof(2, deadline)
    expect(() =>
      ordinaryAuthorizationAttemptChallenge(
        ordinaryRecord({ ceremonyLifetimeSeconds: 2 }),
        JSON.stringify({
          ...valid,
          attempt_capability: maximumCapability,
          expires_in: 2,
        }),
        maximum,
      ),
    ).toThrow(/attempt deadline is invalid/)
  })

  it('bounds response headers, body presence, and an already-aborted read', async () => {
    const controller = new AbortController()
    controller.abort()
    await expect(
      readBoundedOrdinaryAuthorizationResponse(
        new Response('body'),
        controller.signal,
        32,
        'test response',
      ),
    ).rejects.toThrow(/timed out/)

    await expect(
      readBoundedOrdinaryAuthorizationResponse(
        new Response('body', {
          headers: { 'Content-Length': 'not-a-number' },
        }),
        new AbortController().signal,
        32,
        'test response',
      ),
    ).rejects.toThrow(/too large/)

    await expect(
      readBoundedOrdinaryAuthorizationResponse(
        new Response(null),
        new AbortController().signal,
        32,
        'test response',
      ),
    ).rejects.toThrow(/body is missing/)
  })

  it('refuses navigation after admitted authority expires', () => {
    const evaluatedAt = Date.UTC(2030, 0, 1)
    const expiredAt = evaluatedAt - 60_000
    const clock = vi.spyOn(Date, 'now').mockReturnValue(evaluatedAt)
    try {
      expect(() =>
        ordinaryAuthorizationNavigationURL(
          ordinaryRecord({
            parPhase: 'admitted',
            requestUri: REQUEST_URI,
            terminalProof: terminalProof(1, expiredAt),
            attemptExpiresAtMs: expiredAt,
          }),
        ),
      ).toThrow(/admitted root is expired/)
    } finally {
      clock.mockRestore()
    }
  })
})
