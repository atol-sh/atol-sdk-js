import type { DPoPKeyManager } from '../dpop/dpop'
import type { AuthorizationCodeCallback } from './oidc'
import {
  CALLBACK_EXCHANGE_TIMEOUT_MS,
  OrdinaryAuthorizationPendingError,
  type OrdinaryAuthorizationCallbackCustody,
  type OrdinaryAuthorizationCallbackRecovery,
} from './ordinary-authorization-model'
import {
  exchangeCode,
  type TokenResponse,
} from './silent-renew'
import {
  NetworkError,
  OAuthProtocolError,
  RecoveryAction,
  classifyRenewalError,
} from './token-recovery'

export interface OrdinaryAuthorizationExchangeBinding {
  issuer: string
  clientId: string
  useDPoP: boolean
  requireDPoP: boolean
}

export function assertOrdinaryAuthorizationDPoPBinding(
  binding: OrdinaryAuthorizationExchangeBinding,
  custody: OrdinaryAuthorizationCallbackCustody,
): DPoPKeyManager | null {
  const dpop = custody.dpopKey
  if (binding.useDPoP && !dpop && binding.requireDPoP) {
    throw new Error(
      'OIDC callback is missing its DPoP authorization binding',
    )
  }
  if (!binding.useDPoP && dpop) {
    throw new Error(
      'OIDC callback has an unexpected DPoP authorization binding',
    )
  }
  return dpop
}

export async function exchangeOrdinaryAuthorizationCode(
  binding: OrdinaryAuthorizationExchangeBinding,
  callback: AuthorizationCodeCallback,
  dpop: DPoPKeyManager | null,
): Promise<TokenResponse> {
  const controller = new AbortController()
  const timeout = setTimeout(
    () => controller.abort(),
    CALLBACK_EXCHANGE_TIMEOUT_MS,
  )
  try {
    return await exchangeCode(
      binding.issuer,
      binding.clientId,
      callback.code,
      callback.redirectUri,
      callback.codeVerifier,
      dpop ?? undefined,
      { signal: controller.signal },
    )
  } finally {
    clearTimeout(timeout)
  }
}

export function uncertainOrdinaryCodeExchange(
  error: unknown,
): boolean {
  return (
    error instanceof NetworkError ||
    (error instanceof OAuthProtocolError &&
      classifyRenewalError(error) === RecoveryAction.Retry)
  )
}

export async function compensateOrdinaryAuthorizationCode(
  binding: OrdinaryAuthorizationExchangeBinding,
  custody: OrdinaryAuthorizationCallbackCustody,
  callback: AuthorizationCodeCallback,
  dpop: DPoPKeyManager | null,
): Promise<void> {
  try {
    await exchangeOrdinaryAuthorizationCode(
      binding,
      callback,
      dpop,
    )
  } catch (error) {
    if (
      error instanceof OAuthProtocolError &&
      error.code === 'invalid_grant'
    ) {
      await custody.discard()
      return
    }
    await custody.release()
    throw new OrdinaryAuthorizationPendingError()
  }
  await custody.release()
  throw new OrdinaryAuthorizationPendingError()
}

export async function settleRecoveredOrdinaryAuthorization(
  binding: OrdinaryAuthorizationExchangeBinding,
  recovery: OrdinaryAuthorizationCallbackRecovery,
): Promise<void> {
  let dpop: DPoPKeyManager | null
  try {
    dpop = assertOrdinaryAuthorizationDPoPBinding(
      binding,
      recovery.custody,
    )
  } catch (error) {
    await recovery.custody.release()
    throw error
  }
  if (!recovery.custody.compensationRequired) {
    try {
      await exchangeOrdinaryAuthorizationCode(
        binding,
        recovery.callback,
        dpop,
      )
    } catch (error) {
      if (
        error instanceof OAuthProtocolError &&
        error.code === 'invalid_grant'
      ) {
        await recovery.custody.discard()
        return
      }
      await recovery.custody.release()
      throw new OrdinaryAuthorizationPendingError()
    }
    try {
      await recovery.custody.markCodeIssued()
    } catch {
      throw new OrdinaryAuthorizationPendingError()
    }
  }
  await compensateOrdinaryAuthorizationCode(
    binding,
    recovery.custody,
    recovery.callback,
    dpop,
  )
}

export function stripOrdinaryAuthorizationResponseFromHistory(
  redirectUri: string,
): void {
  if (typeof window === 'undefined') {
    throw new Error(
      'ordinary browser authorization: browser history is unavailable',
    )
  }
  let redirect: URL
  try {
    redirect = new URL(redirectUri)
  } catch {
    throw new Error(
      'ordinary browser authorization: redirect URI is invalid',
    )
  }
  if (
    redirect.username !== '' ||
    redirect.password !== '' ||
    redirect.hash !== '' ||
    window.location.origin !== redirect.origin
  ) {
    throw new Error(
      'ordinary browser authorization: redirect URI does not match this browser',
    )
  }
  const target = `${redirect.pathname}${redirect.search}`
  window.history.replaceState(
    window.history.state,
    document.title,
    target,
  )
  const retained = new URL(window.location.href)
  if (
    retained.origin !== redirect.origin ||
    retained.pathname !== redirect.pathname ||
    retained.search !== redirect.search ||
    retained.hash !== ''
  ) {
    throw new Error(
      'ordinary browser authorization: response URL cleanup failed',
    )
  }
}
