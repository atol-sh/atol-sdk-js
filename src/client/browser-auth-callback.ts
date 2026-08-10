import type { DPoPKeyManager } from '../dpop/dpop'
import {
  currentCredentialAuthority,
  credentialGenerationSnapshot,
} from '../oidc/credential-generation'
import {
  readAuthorizationCodeResponseState,
  requireAuthorizationCodeCallback,
} from '../oidc/oidc'
import {
  assertOrdinaryAuthorizationDPoPBinding,
  compensateOrdinaryAuthorizationCode,
  exchangeOrdinaryAuthorizationCode,
  stripOrdinaryAuthorizationResponseFromHistory,
} from '../oidc/ordinary-authorization-exchange'
import { OrdinaryAuthorizationPendingError } from '../oidc/ordinary-authorization'
import {
  ResponseVaultDeliveryUnavailableError,
  type ResponseVaultGrant,
} from '../oidc/response-vault'
import { takeResponseVaultDeliveryReturnTo } from '../oidc/response-vault-contract'
import {
  LoginRequiredError,
  type TokenResponse,
} from '../oidc/silent-renew'
import {
  NetworkError,
  OAuthProtocolError,
} from '../oidc/token-recovery'
import type {
  BrowserAuthCallbackOperations,
  BrowserAuthRuntime,
  SilentCredentialGrant,
} from './browser-auth-context'
import { StaleCredentialTransactionError } from './browser-auth-support'

export function createBrowserAuthCallbackOperations(
  runtime: BrowserAuthRuntime,
): BrowserAuthCallbackOperations {
  function completeLogin() {
    if (!runtime.lifecycleOps.isCallbackUrl()) {
      return Promise.resolve(runtime.sessionOps.session())
    }
    if (runtime.completeLoginPromise) {
      return runtime.completeLoginPromise
    }

    const completionEpoch = runtime.credentialEpoch
    const completion = (async () => {
      let returnToApplied = false
      let preserveCallbackForRetry = false
      try {
        const callbackAuthority = currentCredentialAuthority(
          runtime.credentialGenerationBinding,
        )
        if (callbackAuthority.signedOut) {
          if (runtime.responseVault) {
            if (
              await runtime.lifecycleOps.settleSignedOutStartup(
                callbackAuthority.generation,
              )
            ) {
              throw new StaleCredentialTransactionError()
            }
          } else {
            await runtime.lifecycleOps.ensureRuntimeInitialized()
            const callback =
              await readAuthorizationCodeResponseState(
                runtime.manager,
                window.location.href,
              )
            if (callback.credentialGeneration) {
              await runtime.ordinaryAuthorization!.discardCallback(
                callback,
                callback.credentialGeneration,
              )
            }
            throw new StaleCredentialTransactionError()
          }
        }
        const completionGeneration = credentialGenerationSnapshot(
          runtime.credentialGenerationBinding,
        )
        await runtime.lifecycleOps.ensureRuntimeInitialized()
        if (completionEpoch !== runtime.credentialEpoch) {
          throw new StaleCredentialTransactionError()
        }
        runtime.sessionOps.assertCredentialAuthority(
          completionGeneration,
        )
        const startEpoch = completionEpoch
        if (runtime.responseVault) {
          let responseVaultGrant: ResponseVaultGrant
          try {
            responseVaultGrant =
              await runtime.responseVault.completeInteractive(
                completionGeneration,
              )
          } catch (error) {
            if (
              !(
                error instanceof
                ResponseVaultDeliveryUnavailableError
              )
            ) {
              throw error
            }
            runtime.sessionOps.clearSession()
            const recoveryEpoch = runtime.credentialEpoch
            const recovery =
              await runtime.renewalOps.renewViaIframe(
                undefined,
                completionGeneration,
              )
            await runtime.credentialOps.applyAuthorizationGrant(
              recovery,
              {
                epoch: recoveryEpoch,
                expectedNonce: recovery.nonce,
                dpopKey: recovery.dpopKey,
                replaceDPoPKey: true,
                credentialGeneration: completionGeneration,
              },
            )
            returnToApplied = runtime.applyReturnTo(
              takeResponseVaultDeliveryReturnTo(error),
            )
            return runtime.sessionOps.session()
          }
          const grant: SilentCredentialGrant = {
            tokens: responseVaultGrant.tokens,
            nonce: responseVaultGrant.nonce,
            dpopKey: responseVaultGrant.dpopKey,
            responseVaultGrant,
          }
          await runtime.credentialOps.applyAuthorizationGrant(grant, {
            epoch: startEpoch,
            expectedNonce: grant.nonce,
            dpopKey: grant.dpopKey,
            replaceDPoPKey: true,
            credentialGeneration: completionGeneration,
          })
          returnToApplied = runtime.applyReturnTo(
            responseVaultGrant.returnTo,
          )
          return runtime.sessionOps.session()
        }
        if (
          await runtime.ordinaryAuthorization!.finishPendingCleanup(
            completionGeneration,
          )
        ) {
          throw new Error(
            'ordinary browser authorization callback was already settled',
          )
        }
        const callbackState =
          await readAuthorizationCodeResponseState(
            runtime.manager,
            window.location.href,
          )
        const callbackGeneration =
          callbackState.credentialGeneration
        if (
          !callbackGeneration ||
          callbackGeneration.logout !==
            completionGeneration.logout ||
          callbackGeneration.tabOwner !==
            completionGeneration.tabOwner
        ) {
          throw new StaleCredentialTransactionError()
        }
        runtime.sessionOps.assertCredentialAuthority(
          callbackGeneration,
        )
        const callbackCustody =
          await runtime.ordinaryAuthorization!.claimCallback(
            callbackState,
            callbackGeneration,
        )
        try {
          stripOrdinaryAuthorizationResponseFromHistory(
            callbackState.redirectUri,
          )
        } catch (error) {
          await callbackCustody.release()
          throw error
        }
        let callback
        try {
          callback =
            requireAuthorizationCodeCallback(callbackState)
        } catch (error) {
          if (callbackState.error) {
            await callbackCustody.discard()
          } else {
            await callbackCustody.release()
          }
          throw error
        }
        let callbackDPoP: DPoPKeyManager | null
        try {
          callbackDPoP =
            assertOrdinaryAuthorizationDPoPBinding(
              runtime.ordinaryExchangeBinding,
              callbackCustody,
            )
        } catch (error) {
          await callbackCustody.release()
          throw error
        }
        if (callbackCustody.compensationRequired) {
          await compensateOrdinaryAuthorizationCode(
            runtime.ordinaryExchangeBinding,
            callbackCustody,
            callback,
            callbackDPoP,
          )
          throw new Error(
            'ordinary browser authorization compensation completed',
          )
        }
        let tokens: TokenResponse
        try {
          runtime.sessionOps.assertCredentialAuthority(
            callbackGeneration,
          )
          tokens = await exchangeOrdinaryAuthorizationCode(
            runtime.ordinaryExchangeBinding,
            callback,
            callbackDPoP,
          )
        } catch (error) {
          if (
            error instanceof OAuthProtocolError &&
            error.code === 'invalid_grant'
          ) {
            await callbackCustody.discard()
            throw error
          }
          preserveCallbackForRetry = true
          await callbackCustody.release()
          throw new OrdinaryAuthorizationPendingError()
        }
        try {
          await callbackCustody.markCodeIssued()
        } catch {
          preserveCallbackForRetry = true
          throw new OrdinaryAuthorizationPendingError()
        }
        try {
          await runtime.credentialOps.applyTokens(tokens, {
            epoch: startEpoch,
            expectedNonce: callback.nonce,
            dpopKey: callbackDPoP,
            replaceDPoPKey: true,
            credentialGeneration: callbackGeneration,
          })
        } catch (error) {
          await compensateOrdinaryAuthorizationCode(
            runtime.ordinaryExchangeBinding,
            callbackCustody,
            callback,
            callbackDPoP,
          )
          throw error
        }
        await callbackCustody.complete()
        returnToApplied = runtime.applyReturnTo(callback.returnTo)
        return runtime.sessionOps.session()
      } catch (error) {
        runtime.sessionOps.clearSession()
        if (error instanceof OrdinaryAuthorizationPendingError) {
          preserveCallbackForRetry = true
          throw error
        }
        if (
          runtime.responseVault &&
          (error instanceof NetworkError ||
            error instanceof OAuthProtocolError ||
            error instanceof LoginRequiredError)
        ) {
          throw error
        }
        throw new Error(
          'OIDC callback failed. Please sign in again.',
        )
      } finally {
        if (
          !runtime.responseVault &&
          !returnToApplied &&
          !preserveCallbackForRetry &&
          typeof window !== 'undefined'
        ) {
          const redirect = new URL(runtime.redirectUri)
          window.history.replaceState(
            {},
            document.title,
            `${redirect.pathname}${redirect.search}`,
          )
        }
      }
    })().finally(() => {
      if (runtime.completeLoginPromise === completion) {
        runtime.completeLoginPromise = null
      }
    })
    runtime.completeLoginPromise = completion
    return completion
  }

  return { completeLogin }
}
