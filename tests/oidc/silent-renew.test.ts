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
  DEFAULT_AUTHORIZE_TIMEOUT_MS,
  DEFAULT_SILENT_RENEW_RETRY_COUNT,
  silentAuthorizeURL,
} from '../../src/oidc/silent-renew'

const AUTHORITY = 'https://auth.atol.test'
const AUTHORIZATION_URL =
  `${AUTHORITY}/auth/authorize?client_id=atol_kid_test` +
  '&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const BASE_OPTIONS = {
  authority: AUTHORITY,
  clientId: 'atol_kid_test',
  admittedAuthorizationUrl: AUTHORIZATION_URL,
  timeoutMs: 500,
}

function currentIframe(): HTMLIFrameElement {
  const iframe = document.querySelector('iframe')
  if (!(iframe instanceof HTMLIFrameElement)) {
    throw new Error('silent authorization iframe is missing')
  }
  return iframe
}

function postAuthorizationResponse(
  iframe: HTMLIFrameElement,
  origin: string,
  response: Record<string, unknown>,
  source: MessageEventSource | null = iframe.contentWindow,
): void {
  window.dispatchEvent(
    new MessageEvent('message', {
      data: { type: 'authorization_response', response },
      origin,
      source,
    }),
  )
}

afterEach(() => {
  document.body.innerHTML = ''
  vi.restoreAllMocks()
})

describe('silent admitted authorization iframe', () => {
  it('retains the bounded timeout and retry constants', () => {
    expect(DEFAULT_AUTHORIZE_TIMEOUT_MS).toBe(60_000)
    expect(DEFAULT_SILENT_RENEW_RETRY_COUNT).toBe(3)
  })

  it('navigates the exact admitted URL without constructing raw parameters', async () => {
    const pending = silentAuthorizeURL(BASE_OPTIONS)
    const iframe = currentIframe()
    expect(iframe.src).toBe(AUTHORIZATION_URL)
    expect(Array.from(new URL(iframe.src).searchParams.keys())).toEqual([
      'client_id',
      'request_uri',
    ])
    expect(iframe.referrerPolicy).toBe('no-referrer')

    postAuthorizationResponse(iframe, AUTHORITY, {
      code: 'authorization-code',
      state: 'state-value',
    })
    await expect(pending).resolves.toEqual({
      code: 'authorization-code',
      state: 'state-value',
    })
    expect(iframe.parentNode).toBeNull()
  })

  it.each([
    [
      'authority path',
      {
        authority: `${AUTHORITY}/tenant`,
      },
    ],
    [
      'untrustworthy HTTP authority',
      {
        authority: 'http://auth.atol.test',
        admittedAuthorizationUrl:
          AUTHORIZATION_URL.replace(
            AUTHORITY,
            'http://auth.atol.test',
          ),
      },
    ],
    [
      'authorization endpoint origin',
      {
        admittedAuthorizationUrl:
          AUTHORIZATION_URL.replace(AUTHORITY, 'https://attacker.test'),
      },
    ],
    [
      'authorization endpoint path',
      {
        admittedAuthorizationUrl:
          AUTHORIZATION_URL.replace('/auth/authorize', '/authorize'),
      },
    ],
    [
      'URL userinfo',
      {
        admittedAuthorizationUrl:
          AUTHORIZATION_URL.replace('https://', 'https://user@'),
      },
    ],
    [
      'URL fragment',
      {
        admittedAuthorizationUrl: `${AUTHORIZATION_URL}#fragment`,
      },
    ],
    [
      'duplicate client_id',
      {
        admittedAuthorizationUrl:
          `${AUTHORIZATION_URL}&client_id=atol_kid_test`,
      },
    ],
    [
      'extra query parameter',
      {
        admittedAuthorizationUrl:
          `${AUTHORIZATION_URL}&response_type=code`,
      },
    ],
    [
      'client binding',
      {
        clientId: 'atol_kid_other',
      },
    ],
    [
      'non-canonical request_uri',
      {
        admittedAuthorizationUrl:
          `${AUTHORITY}/auth/authorize?client_id=atol_kid_test` +
          '&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Anot-canonical',
      },
    ],
  ])('rejects an invalid admitted PAR %s before navigation', (_, overrides) => {
    expect(() =>
      silentAuthorizeURL({
        ...BASE_OPTIONS,
        ...overrides,
      }),
    ).toThrow(/admitted PAR navigation URL is invalid/)
    expect(document.querySelector('iframe')).toBeNull()
  })

  it('requires the exact issuer origin and iframe source', async () => {
    const pending = silentAuthorizeURL(BASE_OPTIONS)
    const iframe = currentIframe()
    let settled = false
    void pending.finally(() => {
      settled = true
    })

    postAuthorizationResponse(iframe, 'https://attacker.test', {
      code: 'attacker-code',
      state: 'state-value',
    })
    postAuthorizationResponse(
      iframe,
      AUTHORITY,
      { code: 'sibling-code', state: 'state-value' },
      window,
    )
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(settled).toBe(false)

    postAuthorizationResponse(iframe, AUTHORITY, {
      code: 'authorization-code',
      state: 'state-value',
    })
    await expect(pending).resolves.toMatchObject({
      code: 'authorization-code',
    })
  })

  it('rejects a missing response state', async () => {
    const pending = silentAuthorizeURL(BASE_OPTIONS)
    const iframe = currentIframe()
    postAuthorizationResponse(iframe, AUTHORITY, {
      code: 'authorization-code',
    })
    await expect(pending).rejects.toThrow(/missing state/)
  })

  it('can enforce a caller-owned expected state', async () => {
    const pending = silentAuthorizeURL({
      ...BASE_OPTIONS,
      expectedState: 'expected-state',
    })
    const iframe = currentIframe()
    postAuthorizationResponse(iframe, AUTHORITY, {
      code: 'authorization-code',
      state: 'substituted-state',
    })
    await expect(pending).rejects.toThrow(/state mismatch/)
  })

  it('returns an OAuth error for custody-aware caller settlement', async () => {
    const pending = silentAuthorizeURL(BASE_OPTIONS)
    const iframe = currentIframe()
    postAuthorizationResponse(iframe, AUTHORITY, {
      error: 'login_required',
      state: 'state-value',
    })
    await expect(pending).resolves.toEqual({
      error: 'login_required',
      state: 'state-value',
    })
  })

  it('times out and removes the iframe', async () => {
    const pending = silentAuthorizeURL({
      ...BASE_OPTIONS,
      timeoutMs: 20,
    })
    const iframe = currentIframe()
    await expect(pending).rejects.toThrow(/timed out/)
    expect(iframe.parentNode).toBeNull()
  })
})
