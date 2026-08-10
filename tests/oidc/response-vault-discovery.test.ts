/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import { describe, expect, it, vi } from 'vitest'
import { NetworkError } from '../../src/oidc/token-recovery'
import {
  CLIENT_ORIGIN,
  DISCOVERY_URL,
  ISSUER,
  OPAQUE_A,
  OPAQUE_C,
  bootstrap,
  discoveryDocument,
  expectNoActiveReference,
  installFetch,
  installResponseVaultProtocolHooks,
  issuerBootstrap,
  jsonResponse,
  newVault,
  noContent,
  pushed,
} from './response-vault-protocol-test-support'

installResponseVaultProtocolHooks()

describe('response-vault discovery authority', () => {
  it('validates and caches one bounded no-credential discovery request', async () => {
    const document = discoveryDocument()
    document.scopes_supported = ['openid', 'profile']
    document.claims_supported = ['sub', 'iss', 'aud']
    document.ui_locales_supported = {
      defaults: ['en'],
      aliases: { english: 'en' },
    }
    installFetch(
      [
        bootstrap(OPAQUE_A),
        pushed(),
        issuerBootstrap(OPAQUE_C),
        noContent(),
        noContent(),
      ],
      jsonResponse(document, 200),
    )
    const vault = newVault()

    await vault.beginInteractive()
    await vault.invalidateLifecycle()

    const discoveries = vi
      .mocked(fetch)
      .mock.calls.filter(([input]) => String(input) === DISCOVERY_URL)
    expect(discoveries).toHaveLength(1)
    expect(discoveries[0][1]).toMatchObject({
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: { Accept: 'application/json' },
    })
  })

  it.each([
    [
      'missing response mode registration',
      () => {
        const document = discoveryDocument()
        document.response_modes_supported = ['query']
        return document
      },
      /response modes are invalid/,
    ],
    [
      'missing browser metadata',
      () => {
        const document = discoveryDocument()
        delete document.atol_console_browser_authorization
        return document
      },
      /browser authorization metadata is invalid/,
    ],
    [
      'unknown browser metadata member',
      () => {
        const document = discoveryDocument()
        const metadata = document.atol_console_browser_authorization as Record<
          string,
          unknown
        >
        metadata.unregistered_endpoint = `${CLIENT_ORIGIN}/unregistered`
        return document
      },
      /browser authorization metadata is invalid/,
    ],
    [
      'configured client mismatch',
      () => {
        const document = discoveryDocument()
        const metadata = document.atol_console_browser_authorization as Record<
          string,
          unknown
        >
        metadata.client_id = 'different-client'
        return document
      },
      /browser authorization binding is invalid/,
    ],
    [
      'configured issuer mismatch',
      () => {
        const document = discoveryDocument()
        document.issuer = 'https://other.example.com'
        return document
      },
      /discovered issuer is invalid/,
    ],
    [
      'missing standard token endpoint',
      () => {
        const document = discoveryDocument()
        delete document.token_endpoint
        return document
      },
      /token endpoint is invalid/,
    ],
    [
      'mismatched standard token endpoint',
      () => {
        const document = discoveryDocument()
        document.token_endpoint = `${ISSUER}/other-token`
        return document
      },
      /token endpoint is invalid/,
    ],
    [
      'mismatched standard authorization endpoint',
      () => {
        const document = discoveryDocument()
        document.authorization_endpoint = `${ISSUER}/other-authorize`
        return document
      },
      /standard authorization endpoint is invalid/,
    ],
    [
      'wrong endpoint origin',
      () => {
        const document = discoveryDocument()
        const metadata = document.atol_console_browser_authorization as Record<
          string,
          unknown
        >
        metadata.relay_endpoint =
          'https://attacker.example.com/auth/browser/v1/relay'
        return document
      },
      /relay endpoint is invalid/,
    ],
    [
      'wrong endpoint path',
      () => {
        const document = discoveryDocument()
        const metadata = document.atol_console_browser_authorization as Record<
          string,
          unknown
        >
        metadata.authorization_init_endpoint = `${ISSUER}/auth/browser/v1/wrong-init`
        return document
      },
      /authorization init endpoint is invalid/,
    ],
    [
      'endpoint query',
      () => {
        const document = discoveryDocument()
        const metadata = document.atol_console_browser_authorization as Record<
          string,
          unknown
        >
        metadata.bootstrap_endpoint = `${CLIENT_ORIGIN}/auth/browser/v1/bootstrap?authority=other`
        return document
      },
      /bootstrap endpoint is invalid/,
    ],
  ])(
    'rejects %s before creating authority',
    async (_name, create, expected) => {
      installFetch([], jsonResponse(create(), 200))

      await expect(newVault().beginInteractive()).rejects.toThrow(expected)

      expectNoActiveReference()
      expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1)
    },
  )

  it.each([
    [
      'a duplicate nested member',
      `${JSON.stringify(discoveryDocument()).replace(
        '"version":1',
        '"version":1,"version":1',
      )}`,
      /duplicate member/,
    ],
    [
      'trailing data',
      `${JSON.stringify(discoveryDocument())} true`,
      /trailing data/,
    ],
    ['malformed JSON', '{"issuer":', /supported primitive|malformed/],
    [
      'an oversized document',
      JSON.stringify({
        ...discoveryDocument(),
        padding: 'x'.repeat(33 * 1024),
      }),
      /response body exceeds the limit|response size is invalid/,
    ],
  ])('rejects %s', async (_name, body, expected) => {
    installFetch(
      [],
      new Response(body, {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await expect(newVault().beginInteractive()).rejects.toThrow(expected)

    expectNoActiveReference()
  })

  it('does not cache a failed discovery request', async () => {
    let attempts = 0
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        if (String(input) !== DISCOVERY_URL) {
          throw new Error(`unexpected fetch: ${String(input)}`)
        }
        attempts++
        if (attempts === 1) throw new TypeError('discovery connection reset')
        return jsonResponse(discoveryDocument(), 200)
      }),
    )
    const vault = newVault()
    const internal = vault as unknown as {
      endpointRegistry(): Promise<unknown>
    }

    await expect(internal.endpointRegistry()).rejects.toBeInstanceOf(
      NetworkError,
    )
    await expect(internal.endpointRegistry()).resolves.toBeDefined()

    expect(attempts).toBe(2)
  })

  it('aborts discovery at the configured operation deadline', async () => {
    let aborted = false
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (
          input: string | URL | Request,
          init?: RequestInit,
        ): Promise<Response> => {
          if (String(input) !== DISCOVERY_URL) {
            return Promise.reject(
              new Error(`unexpected fetch: ${String(input)}`),
            )
          }
          return new Promise((_resolve, reject) => {
            const signal = init?.signal
            if (!signal) {
              reject(new Error('discovery request has no abort signal'))
              return
            }
            signal.addEventListener(
              'abort',
              () => {
                aborted = true
                reject(new DOMException('aborted', 'AbortError'))
              },
              { once: true },
            )
          })
        },
      ),
    )

    await expect(
      newVault({ operationTimeoutMs: 25 }).beginInteractive(),
    ).rejects.toBeInstanceOf(NetworkError)

    expect(aborted).toBe(true)
    expectNoActiveReference()
  })

  it('aborts an in-flight discovery when the lifecycle is invalidated', async () => {
    let aborted = false
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (
          input: string | URL | Request,
          init?: RequestInit,
        ): Promise<Response> => {
          if (String(input) !== DISCOVERY_URL) {
            return Promise.reject(
              new Error(`unexpected fetch: ${String(input)}`),
            )
          }
          return new Promise((_resolve, reject) => {
            init?.signal?.addEventListener(
              'abort',
              () => {
                aborted = true
                reject(new DOMException('aborted', 'AbortError'))
              },
              { once: true },
            )
          })
        },
      ),
    )
    const vault = newVault({ operationTimeoutMs: 5_000 })
    const pending = vault.beginInteractive()
    void pending.catch(() => undefined)
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))

    await vault.invalidateLifecycle()
    await expect(pending).rejects.toBeInstanceOf(NetworkError)

    expect(aborted).toBe(true)
    expectNoActiveReference()
  })
})
