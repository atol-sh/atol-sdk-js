/**
 * @vitest-environment-options {"url":"http://localhost/"}
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  assertCredentialGenerationSnapshot,
  assertLogoutGeneration,
  assertTabOwnerGeneration,
  credentialGenerationForLogin,
  credentialGenerationSnapshot,
  currentCredentialAuthority,
  currentLogoutGeneration,
  currentTabOwnerGeneration,
  isCredentialGeneration,
  rotateLogoutGeneration,
  rotateTabOwnerGeneration,
} from '../../src/oidc/credential-generation'

function memoryStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => {
      values.delete(key)
    },
    setItem: (key, value) => {
      values.set(key, String(value))
    },
  }
}

Object.defineProperty(window, 'localStorage', {
  configurable: true,
  value: memoryStorage(),
})

const binding = {
  issuer: 'https://id.example.test',
  clientId: 'example-client',
  redirectUri: 'http://localhost/callback',
}

beforeEach(() => {
  window.history.replaceState({}, '', '/')
  window.localStorage.clear()
  window.sessionStorage.clear()
})

describe('credential generations', () => {
  it('uses one stable origin-wide initial logout generation', () => {
    const initial = currentLogoutGeneration(binding)
    expect(initial).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(currentLogoutGeneration({
      ...binding,
      redirectUri: 'http://localhost/another-callback',
    })).toBe(initial)
  })

  it('does not merge distinct issuer paths on the same authority host', () => {
    const first = currentLogoutGeneration({
      ...binding,
      issuer: 'https://id.example.test/realm-a',
    })
    const second = currentLogoutGeneration({
      ...binding,
      issuer: 'https://id.example.test/realm-b',
    })

    expect(second).not.toBe(first)
    expect(window.localStorage.length).toBe(2)
  })

  it('rotates logout authority synchronously across redirect paths', () => {
    const previous = currentLogoutGeneration(binding)
    const next = rotateLogoutGeneration(binding)

    expect(next).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(next).not.toBe(previous)
    expect(() => assertLogoutGeneration(binding, previous)).toThrow(
      /invalidated/,
    )
    expect(currentCredentialAuthority(binding)).toEqual({
      generation: next,
      signedOut: true,
    })
    expect(currentLogoutGeneration({
      ...binding,
      redirectUri: 'http://localhost/another-callback',
    })).toBe(next)
  })

  it('overwrites corrupt logout state instead of blocking invalidation', () => {
    window.localStorage.setItem(
      window.localStorage.key(0) ?? 'unrelated',
      'unrelated',
    )
    currentLogoutGeneration(binding)
    const generationKey = Array.from(
      { length: window.localStorage.length },
      (_, index) => window.localStorage.key(index),
    ).find((key) => key?.includes(':logout:'))
    rotateLogoutGeneration(binding)
    const actualKey = generationKey ??
      Array.from(
        { length: window.localStorage.length },
        (_, index) => window.localStorage.key(index),
      ).find((key) => key?.includes(':logout:'))
    expect(actualKey).toBeTruthy()
    window.localStorage.setItem(actualKey!, 'not canonical')

    expect(() => currentLogoutGeneration(binding)).toThrow(/corrupt/)
    expect(rotateLogoutGeneration(binding)).toMatch(
      /^[A-Za-z0-9_-]{43}$/,
    )
    expect(() =>
      assertLogoutGeneration(binding, currentLogoutGeneration(binding)),
    ).toThrow(/invalidated/)

    const active = credentialGenerationForLogin(binding)
    expect(() => assertLogoutGeneration(binding, active.logout)).not.toThrow()
    expect(currentCredentialAuthority(binding).signedOut).toBe(false)
  })

  it('does not resurrect old authority after the logout key is deleted', () => {
    const oldSnapshot = credentialGenerationSnapshot(binding)
    const rotated = rotateLogoutGeneration(binding)
    const tabOwner = currentTabOwnerGeneration(binding)
    const logoutKey = Array.from(
      { length: window.localStorage.length },
      (_, index) => window.localStorage.key(index),
    ).find((key) => key?.includes(':logout:'))

    expect(logoutKey).toBeTruthy()
    expect(tabOwner).toBe(oldSnapshot.tabOwner)
    window.localStorage.removeItem(logoutKey!)

    const reinitialized = currentLogoutGeneration(binding)
    expect(reinitialized).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(reinitialized).not.toBe(oldSnapshot.logout)
    expect(reinitialized).not.toBe(rotated)
    expect(currentTabOwnerGeneration(binding)).toBe(oldSnapshot.tabOwner)
    expect(() =>
      assertCredentialGenerationSnapshot(binding, oldSnapshot),
    ).toThrow(/invalidated/)
  })

  it('keeps a redirect-stable tab owner and rotates it independently', () => {
    const first = currentTabOwnerGeneration(binding)
    expect(currentTabOwnerGeneration(binding)).toBe(first)

    const second = rotateTabOwnerGeneration(binding)
    expect(second).not.toBe(first)
    expect(() => assertTabOwnerGeneration(binding, first)).toThrow(
      /superseded/,
    )
    expect(() => assertTabOwnerGeneration(binding, second)).not.toThrow()
  })

  it('clears a signed-out tombstone only under fresh explicit-login authority', () => {
    const original = credentialGenerationSnapshot(binding)
    const signedOut = rotateLogoutGeneration(binding)
    const persisted = window.localStorage.getItem(
      window.localStorage.key(0)!,
    )

    expect(JSON.parse(persisted!)).toEqual({
      version: 1,
      generation: signedOut,
      status: 'signed_out',
    })
    expect(() =>
      assertCredentialGenerationSnapshot(binding, {
        logout: signedOut,
        tabOwner: original.tabOwner,
      }),
    ).toThrow(/invalidated/)

    const login = credentialGenerationForLogin(binding)
    expect(login.logout).not.toBe(signedOut)
    expect(login.tabOwner).toBe(original.tabOwner)
    expect(currentCredentialAuthority(binding)).toEqual({
      generation: login.logout,
      signedOut: false,
    })
    expect(() =>
      assertCredentialGenerationSnapshot(binding, login),
    ).not.toThrow()
  })

  it('validates the combined authorization snapshot', () => {
    const snapshot = credentialGenerationSnapshot(binding)
    expect(() =>
      assertCredentialGenerationSnapshot(binding, snapshot),
    ).not.toThrow()

    rotateLogoutGeneration(binding)
    expect(() =>
      assertCredentialGenerationSnapshot(binding, snapshot),
    ).toThrow(/invalidated/)
  })

  it('rejects noncanonical snapshots', () => {
    expect(isCredentialGeneration('0')).toBe(false)
    expect(isCredentialGeneration('A'.repeat(43))).toBe(true)
    expect(isCredentialGeneration('A'.repeat(43) + '=')).toBe(false)
    expect(() => assertLogoutGeneration(binding, 'bad')).toThrow(
      /invalidated/,
    )
  })

  it.each([
    ['invalid issuer URL', { ...binding, issuer: 'not a URL' }],
    ['non-network issuer', { ...binding, issuer: 'ftp://id.example.test' }],
    [
      'issuer with query',
      { ...binding, issuer: 'https://id.example.test?realm=a' },
    ],
    [
      'credentialed redirect',
      { ...binding, redirectUri: 'http://user@localhost/callback' },
    ],
    ['empty client ID', { ...binding, clientId: '' }],
    [
      'different application origin',
      { ...binding, redirectUri: 'https://other.example.test/callback' },
    ],
  ])('rejects an %s binding before reading browser authority', (_name, input) => {
    expect(() => currentLogoutGeneration(input)).toThrow(
      /invalid authorization binding|current origin does not match/,
    )
  })

  it('fails loud when browser storage is unavailable', () => {
    const browserWindow = globalThis.window
    vi.stubGlobal('window', undefined)
    try {
      expect(() => currentLogoutGeneration(binding)).toThrow(
        /browser storage is unavailable/,
      )
    } finally {
      vi.stubGlobal('window', browserWindow)
    }
  })
})
