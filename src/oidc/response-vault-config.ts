import { bytesToBase64Url } from '../crypto/base64url'
import { normalizeSameOriginReturnTo } from './return-to'
import {
  validResponseVaultBinding,
  validResponseVaultIntent,
  type ResponseVaultIntent,
} from './response-vault-storage'
import type { ResponseVaultConfig } from './response-vault-contract'

export function potentiallyTrustworthyURL(parsed: URL): boolean {
  if (parsed.protocol === 'https:') return true
  if (parsed.protocol !== 'http:') return false
  const hostname = parsed.hostname.toLowerCase()
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '[::1]'
  ) {
    return true
  }
  const octets = hostname.split('.').map(Number)
  return (
    octets.length === 4 &&
    octets.every(
      (octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255,
    ) &&
    octets[0] === 127
  )
}

function normalizeOriginURL(raw: string, label: string): string {
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch {
    throw new Error(`response vault: ${label} is not a valid URL`)
  }
  if (
    !potentiallyTrustworthyURL(parsed) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(
      `response vault: ${label} must be HTTPS or a loopback development origin`,
    )
  }
  return parsed.origin
}

function normalizeRedirectURI(raw: string): string {
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch {
    throw new Error('response vault: redirectUri is not a valid URL')
  }
  if (
    !potentiallyTrustworthyURL(parsed) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(
      'response vault: redirectUri must be a clean secure-context URL',
    )
  }
  return parsed.href
}

export function validateConfig(
  config: ResponseVaultConfig,
): ResponseVaultConfig {
  const issuer = normalizeOriginURL(config.issuer, 'issuer')
  const redirectUri = normalizeRedirectURI(config.redirectUri)
  if (new URL(issuer).protocol !== new URL(redirectUri).protocol) {
    throw new Error('response vault: issuer and redirect schemes must match')
  }
  const normalized = { ...config, issuer, redirectUri }
  if (!validResponseVaultBinding(normalized)) {
    throw new Error('response vault: client binding is invalid')
  }
  if (
    config.iframeTimeoutMs !== undefined &&
    (!Number.isInteger(config.iframeTimeoutMs) ||
      config.iframeTimeoutMs <= 0 ||
      config.iframeTimeoutMs > 5 * 60_000)
  ) {
    throw new Error('response vault: iframe timeout is invalid')
  }
  if (
    config.operationTimeoutMs !== undefined &&
    (!Number.isInteger(config.operationTimeoutMs) ||
      config.operationTimeoutMs <= 0 ||
      config.operationTimeoutMs > 60_000)
  ) {
    throw new Error('response vault: operation timeout is invalid')
  }
  return normalized
}

export function validateIntent(
  intent: ResponseVaultIntent,
  redirectUri: string,
): void {
  let returnTo: string | undefined
  try {
    returnTo = normalizeSameOriginReturnTo(intent.returnTo, redirectUri)
  } catch {
    throw new Error('response vault: authorization intent is invalid')
  }
  if (
    !validResponseVaultIntent(intent, redirectUri) ||
    returnTo !== intent.returnTo
  ) {
    throw new Error('response vault: authorization intent is invalid')
  }
}

export function sameIntent(
  left: ResponseVaultIntent,
  right: ResponseVaultIntent,
): boolean {
  return (
    left.prompt === right.prompt &&
    left.maxAge === right.maxAge &&
    left.acrValues === right.acrValues &&
    left.organizationId === right.organizationId &&
    left.returnTo === right.returnTo
  )
}

export function randomOpaque(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return bytesToBase64Url(bytes)
}

export async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier),
  )
  return bytesToBase64Url(new Uint8Array(digest))
}

export function exactCurrentCallback(redirectUri: string): boolean {
  if (typeof window === 'undefined') return false
  const current = new URL(window.location.href)
  return (
    current.origin + current.pathname === redirectUri &&
    current.search === '' &&
    current.hash === ''
  )
}
