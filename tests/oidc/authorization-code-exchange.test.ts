/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'
import {
  exchangeOrdinaryAuthorizationCode,
  stripOrdinaryAuthorizationResponseFromHistory,
  uncertainOrdinaryCodeExchange,
} from '../../src/oidc/ordinary-authorization-exchange'
import {
  AuthorizationCodeExchangeUncertainError,
  OAuthProtocolError,
} from '../../src/oidc/token-recovery'

const binding = {
  issuer: 'https://auth.atol.test',
  clientId: 'atol_kid_test',
  useDPoP: false,
  requireDPoP: false,
}

const callback = {
  code: 'ory_ac_code.signature',
  codeVerifier: 'verifier',
  redirectUri: 'https://app.test/cb',
  nonce: 'nonce',
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('ordinary authorization-code transport', () => {
  it('retains only the registered redirect query after callback claim', () => {
    window.history.replaceState(
      {},
      '',
      '/cb?tenant=alpha&code=secret&state=opaque&session_state=provider#untrusted',
    )

    stripOrdinaryAuthorizationResponseFromHistory(
      'https://app.test/cb?tenant=alpha',
    )

    expect(window.location.href).toBe(
      'https://app.test/cb?tenant=alpha',
    )
  })

  it('bounds a token endpoint that never returns at exactly 30 seconds', async () => {
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise<Response>(() => undefined)),
    )
    let settled = false
    const exchange = exchangeOrdinaryAuthorizationCode(
      binding,
      callback,
      null,
    ).finally(() => {
      settled = true
    })
    const rejection = expect(exchange).rejects.toBeInstanceOf(
      AuthorizationCodeExchangeUncertainError,
    )

    await vi.advanceTimersByTimeAsync(29_999)
    expect(settled).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    await rejection
  })

  it('bounds a successful response whose body never completes', async () => {
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(
                new TextEncoder().encode('{"access_token":"partial'),
              )
            },
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    )
    const exchange = exchangeOrdinaryAuthorizationCode(
      binding,
      callback,
      null,
    )
    const rejection = expect(exchange).rejects.toBeInstanceOf(
      AuthorizationCodeExchangeUncertainError,
    )

    await vi.advanceTimersByTimeAsync(30_000)
    await rejection
  })

  it('classifies a malformed 2xx body as an uncertain consumed code', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response('{"access_token":', {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
        }),
      ),
    )

    await expect(
      exchangeOrdinaryAuthorizationCode(
        binding,
        callback,
        null,
      ),
    ).rejects.toBeInstanceOf(
      AuthorizationCodeExchangeUncertainError,
    )
  })

  it.each([
    [503, 'server_error'],
    [429, 'temporarily_unavailable'],
  ])(
    'keeps HTTP %i OAuth errors retryable',
    async (status, expectedCode) => {
      vi.stubGlobal(
        'fetch',
        vi.fn(async () =>
          new Response(
            JSON.stringify({
              error:
                status === 503 ? 'server_error' : 'slow_down',
            }),
            {
              status,
              headers: {
                'Content-Type': 'application/json',
              },
            },
          ),
        ),
      )

      const error = await exchangeOrdinaryAuthorizationCode(
        binding,
        callback,
        null,
      ).then(
        () => undefined,
        (value: unknown) => value,
      )
      expect(error).toBeInstanceOf(OAuthProtocolError)
      expect((error as OAuthProtocolError).code).toBe(
        expectedCode,
      )
      expect(uncertainOrdinaryCodeExchange(error)).toBe(true)
    },
  )
})
