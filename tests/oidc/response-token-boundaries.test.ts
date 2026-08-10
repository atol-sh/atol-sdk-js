/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import { bytesToBase64Url } from '../../src/crypto/base64url'
import {
  rfc3339NanoMilliseconds,
  rfc3339NanoNanoseconds,
} from '../../src/oidc/rfc3339-nano'
import {
  bootstrapAttemptChallenge,
  bootstrapResponse,
  expectProtocolResponse,
  issuerBootstrapResponse,
  protocolError,
  pushedResponse,
  relaySuccess,
  terminalRelayError,
} from '../../src/oidc/response-vault-wire'
import {
  readBoundedResponseBody,
  validatedTokenResponse,
  waitForTokenTransport,
} from '../../src/oidc/token-endpoint-response'

const OPAQUE = 'A'.repeat(43)
const REQUEST_URI = `urn:ietf:params:oauth:request_uri:${OPAQUE}`

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

function jsonResponse(
  body: Record<string, unknown>,
  status = 200,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('response-vault wire envelope boundaries', () => {
  it('maps malformed and unexpected protocol responses without trusting fields', async () => {
    expect(protocolError(400, {}, 'bootstrap').message).toMatch(
      /malformed error/,
    )
    await expect(
      expectProtocolResponse(
        jsonResponse({ error: 'invalid_request' }, 400),
        201,
        'bootstrap',
      ),
    ).rejects.toMatchObject({ code: 'invalid_request' })
  })

  it('rejects malformed, expired, and overflowed bootstrap authority', () => {
    const now = Date.now()
    const proof = terminalProof(1, now + 60_000)
    const envelope = {
      version: 1,
      csrf_token: OPAQUE,
      bootstrap_terminal_proof: proof,
      expires_in: 60,
    }
    expect(() =>
      bootstrapResponse({ ...envelope, csrf_token: 'bad' }, now),
    ).toThrow(/bootstrap response is invalid/)
    expect(() =>
      bootstrapResponse(
        { ...envelope, bootstrap_terminal_proof: 'bad' },
        now,
      ),
    ).toThrow(/bootstrap terminal proof is invalid/)
    expect(() =>
      bootstrapResponse(envelope, Number.MAX_SAFE_INTEGER),
    ).toThrow(/deadline is invalid/)
    expect(() =>
      bootstrapResponse(envelope, now - 61_000),
    ).toThrow(/invalid bootstrap response/)
  })

  it('requires an exact kind-3 bootstrap attempt capability and deadline', () => {
    const now = Date.UTC(2030, 0, 1)
    const deadline = now + 59_000
    const envelope = {
      error: 'attempt_capability_required',
      attempt_capability: terminalProof(3, deadline),
      expires_in: 60,
      attempt_expires_at: new Date(deadline).toISOString(),
    }
    expect(() =>
      bootstrapAttemptChallenge(
        { ...envelope, error: 'invalid_request' },
        now,
      ),
    ).toThrow(/attempt challenge is invalid/)
    expect(() =>
      bootstrapAttemptChallenge(
        { ...envelope, attempt_capability: terminalProof(1, deadline) },
        now,
      ),
    ).toThrow(/attempt capability is invalid/)
    expect(() =>
      bootstrapAttemptChallenge(
        {
          ...envelope,
          attempt_expires_at: new Date(deadline + 1_000).toISOString(),
        },
        now,
      ),
    ).toThrow(/attempt capability is invalid/)
    expect(() =>
      bootstrapAttemptChallenge(envelope, Number.MAX_SAFE_INTEGER),
    ).toThrow(/attempt deadline is invalid/)
  })

  it('rejects invalid issuer bootstrap, PAR, relay, and terminal envelopes', () => {
    const now = Date.now()
    const proof = terminalProof(1, now + 60_000)
    expect(() =>
      issuerBootstrapResponse(
        { version: 1, csrf_token: 'bad', expires_in: 60 },
        now,
      ),
    ).toThrow(/issuer bootstrap response is invalid/)
    expect(() =>
      issuerBootstrapResponse(
        { version: 1, csrf_token: OPAQUE, expires_in: 1 },
        now - 2_000,
      ),
    ).toThrow(/invalid issuer bootstrap response/)

    const pushed = {
      version: 1,
      transaction_id: OPAQUE,
      request_uri: REQUEST_URI,
      expires_in: 60,
      transaction_expires_in: 600,
      csrf_token: OPAQUE,
      terminal_proof: proof,
    }
    expect(() => pushedResponse({ ...pushed, request_uri: 'bad' }, now)).toThrow(
      /pushed authorization response is invalid/,
    )
    expect(() =>
      pushedResponse({ ...pushed, terminal_proof: 'bad' }, now),
    ).toThrow(/terminal proof is invalid/)

    const relay = {
      version: 1,
      access_token: 'access-token',
      token_type: 'DPoP',
      expires_in: 60,
      scope: 'openid',
      csrf_token: OPAQUE,
    }
    expect(() => relaySuccess({ ...relay, token_type: 'Bearer' })).toThrow(
      /relay token response is invalid/,
    )
    expect(() => relaySuccess({ ...relay, access_token: '' })).toThrow(
      /access token is invalid/,
    )
    expect(
      relaySuccess({
        ...relay,
        refresh_token: 'refresh-token',
        id_token: 'id-token',
      }).tokens,
    ).toMatchObject({
      refresh_token: 'refresh-token',
      id_token: 'id-token',
    })
    expect(() =>
      terminalRelayError({
        version: 1,
        error: 'not_allowed',
        csrf_token: OPAQUE,
      }),
    ).toThrow(/terminal relay error is invalid/)
  })
})

describe('token response and RFC3339 transport boundaries', () => {
  it.each([
    [{ id_token: 7 }, 'ID token'],
    [{ refresh_token: 7 }, 'refresh token'],
    [{ scope: '' }, 'scope'],
  ])('rejects malformed optional token fields %#', async (field, _label) => {
    await expect(
      validatedTokenResponse(
        jsonResponse({
          access_token: 'access-token',
          token_type: 'Bearer',
          expires_in: 60,
          ...field,
        }),
        false,
      ),
    ).rejects.toThrow(/invalid success response/)
  })

  it('retains a valid optional scope', async () => {
    await expect(
      validatedTokenResponse(
        jsonResponse({
          access_token: 'access-token',
          token_type: 'Bearer',
          expires_in: 60,
          scope: 'openid profile',
        }),
        false,
      ),
    ).resolves.toMatchObject({ scope: 'openid profile' })
  })

  it('rejects declared and streamed response bodies over the exact limit', async () => {
    for (const declaredLength of [
      '01',
      '17',
      String(Number.MAX_SAFE_INTEGER + 1),
    ]) {
      await expect(
        readBoundedResponseBody(
          new Response('x', {
            headers: { 'Content-Length': declaredLength },
          }),
          16,
          undefined,
          'token response',
        ),
      ).rejects.toThrow(/exceeds the limit/)
    }
    await expect(
      readBoundedResponseBody(
        new Response('too long'),
        1,
        undefined,
        'token response',
      ),
    ).rejects.toThrow(/exceeds the limit/)
  })

  it('assembles real stream chunks without clearing producer memory', async () => {
    const encoder = new TextEncoder()
    const first = encoder.encode('token ')
    const second = encoder.encode('body')
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(first)
        controller.enqueue(second)
        controller.close()
      },
    })

    await expect(
      readBoundedResponseBody(
        new Response(stream),
        16,
        undefined,
        'token response',
      ),
    ).resolves.toBe('token body')
    expect(new TextDecoder().decode(first)).toBe('token ')
    expect(new TextDecoder().decode(second)).toBe('body')
  })

  it('cancels a real pending stream read when its transport is aborted', async () => {
    let markPullStarted: () => void = () => undefined
    const pullStarted = new Promise<void>((resolve) => {
      markPullStarted = resolve
    })
    const cancel = vi.fn()
    const response = new Response(new ReadableStream<Uint8Array>({
      cancel,
      pull: markPullStarted,
    }))
    const controller = new AbortController()
    const body = readBoundedResponseBody(
      response,
      16,
      controller.signal,
      'token response',
    )

    await pullStarted
    controller.abort()
    await expect(body).rejects.toMatchObject({
      code: 'authorization_code_exchange_uncertain',
    })
    await vi.waitFor(() => expect(cancel).toHaveBeenCalledOnce())
  })

  it('fails closed before observing an already-expired transport', async () => {
    const controller = new AbortController()
    controller.abort()
    await expect(
      waitForTokenTransport(
        Promise.resolve('unused'),
        controller.signal,
        'token response',
      ),
    ).rejects.toMatchObject({
      code: 'authorization_code_exchange_uncertain',
    })
  })

  it('keeps an in-flight abort uncertain after a late transport result', async () => {
    let resolveTransport: (value: string) => void = () => undefined
    const operation = new Promise<string>((resolve) => {
      resolveTransport = resolve
    })
    const controller = new AbortController()
    const result = waitForTokenTransport(
      operation,
      controller.signal,
      'token response',
    )

    controller.abort()
    const uncertain = await result.catch((error: unknown) => error)
    expect(uncertain).toMatchObject({
      code: 'authorization_code_exchange_uncertain',
    })
    resolveTransport('late success')
    await expect(operation).resolves.toBe('late success')
    await expect(result).rejects.toBe(uncertain)
  })

  it.each([
    'not-a-date',
    '1969-01-01T00:00:00Z',
    '2024-01-01T00:00:60Z',
    '2024-02-30T00:00:00Z',
  ])('rejects an invalid RFC3339 deadline: %s', (value) => {
    expect(() => rfc3339NanoNanoseconds(value)).toThrow(
      /deadline is invalid/,
    )
  })

  it('parses whole-second RFC3339 deadlines canonically', () => {
    const value = '2030-01-01T00:00:00Z'
    expect(rfc3339NanoNanoseconds(value)).toBe(
      BigInt(Date.UTC(2030, 0, 1)) * 1_000_000n,
    )
    expect(rfc3339NanoMilliseconds(value)).toBe(
      Date.UTC(2030, 0, 1),
    )
  })
})
