import type { CredentialGenerationSnapshot } from './credential-generation'
import { randomOpaque, sameIntent } from './response-vault-config'
import {
  DEFAULT_IFRAME_TIMEOUT_MS,
  type ResponseVaultEndpoints,
  type ResponseVaultGrant,
} from './response-vault-contract'
import {
  bindResponseVaultFailedInitialization,
} from './response-vault-failed-initialization'
import { ResponseVaultAdmission } from './response-vault-admission'
import {
  beginResponseVaultNavigation,
  claimResponseVaultNavigation,
  claimResponseVaultRejection,
  ResponseVaultAuthorizationBusyError,
  type ResponseVaultAuthorization,
  type ResponseVaultIntent,
} from './response-vault-storage'
import { releaseExecutionLockIfHeld } from './response-vault-storage-lock'
import { NetworkError } from './token-recovery'

export abstract class ResponseVaultNavigation extends ResponseVaultAdmission {
  private relayAfterIframeCallback(
    authorization: ResponseVaultAuthorization,
  ): Promise<ResponseVaultGrant> {
    return this.relay(authorization).catch((error) => {
      throw bindResponseVaultFailedInitialization(
        error,
        authorization,
      )
    })
  }

  async beginInteractive(
    intent: ResponseVaultIntent = {},
    expectedGeneration?: CredentialGenerationSnapshot,
  ): Promise<void> {
    let authorization: ResponseVaultAuthorization | undefined
    try {
      authorization = await this.start(
        'interactive',
        intent,
        expectedGeneration,
      )
      this.assertExpectedGeneration(authorization, expectedGeneration)
      let endpoints: ResponseVaultEndpoints
      try {
        endpoints = await this.endpointRegistry()
      } catch (error) {
        return this.rejectAfterFailure(authorization, error)
      }
      authorization = await beginResponseVaultNavigation(
        authorization,
        authorization.expiresAt,
      )
      try {
        window.location.assign(endpoints.authorization)
      } catch (error) {
        const owner = authorization.navigationOwner
        if (!owner) {
          throw new Error('response vault: navigation owner is unavailable')
        }
        const claimed = await claimResponseVaultRejection(
          authorization,
          owner,
          ['navigating'],
          this.executionLeaseDuration(),
        )
        return this.rejectAfterFailure(claimed, error)
      }
    } finally {
      if (authorization) {
        await releaseExecutionLockIfHeld(
          authorization.reference,
          authorization.executionClaim,
        )
      }
    }
  }

  private waitForCleanIframeCallback(
    authorization: ResponseVaultAuthorization,
    authorizationEndpoint: string,
  ): Promise<void> {
    if (!Number.isSafeInteger(authorization.navigationExpiresAt)) {
      throw new Error(
        'response vault: iframe navigation deadline is unavailable',
      )
    }
    const timeout =
      this.config.iframeTimeoutMs ?? DEFAULT_IFRAME_TIMEOUT_MS
    return new Promise((resolve, reject) => {
      const iframe = document.createElement('iframe')
      let timer: ReturnType<typeof setTimeout> | undefined
      let settled = false
      const cleanup = () => {
        if (timer !== undefined) clearTimeout(timer)
        iframe.removeEventListener('load', onLoad)
        this.ownedWaits.delete(cancel)
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe)
      }
      const finish = (error?: unknown) => {
        if (settled) return
        settled = true
        cleanup()
        if (error) reject(error)
        else resolve()
      }
      const cancel = (reason: Error) => finish(reason)
      const onLoad = () => {
        try {
          const href = iframe.contentWindow?.location.href
          if (!href) return
          const current = new URL(href)
          if (current.origin !== this.clientOrigin) return
          if (
            current.origin + current.pathname !== this.config.redirectUri ||
            current.search !== '' ||
            current.hash !== ''
          ) {
            finish(
              new Error('response vault: iframe returned to an invalid URL'),
            )
            return
          }
          this.assertAuthorizationCurrent(authorization)
          finish()
        } catch (error) {
          if (
            error instanceof DOMException &&
            error.name === 'SecurityError'
          ) {
            return
          }
          finish(error)
        }
      }
      iframe.style.display = 'none'
      iframe.setAttribute('aria-hidden', 'true')
      iframe.referrerPolicy = 'no-referrer'
      this.markOwnedIframe(iframe)
      iframe.addEventListener('load', onLoad)
      this.ownedWaits.add(cancel)
      const remaining = Math.max(
        0,
        Math.min(
          timeout,
          (authorization.navigationExpiresAt as number) - Date.now(),
        ),
      )
      timer = setTimeout(() => {
        finish(
          new NetworkError(
            'response vault: iframe authorization timed out',
          ),
        )
      }, remaining)
      iframe.src = authorizationEndpoint
      document.body.appendChild(iframe)
    })
  }

  async authorizeInIframe(
    intent: ResponseVaultIntent,
    expectedGeneration?: CredentialGenerationSnapshot,
  ): Promise<ResponseVaultGrant> {
    let authorization: ResponseVaultAuthorization | undefined
    try {
      const lifecycleEpoch = this.lifecycleEpoch()
      const existing = await this.activeAuthorization(lifecycleEpoch)
      if (existing) {
        authorization = existing
        this.assertExpectedGeneration(authorization, expectedGeneration)
        if (authorization.mode !== 'iframe') {
          throw new Error('response vault: another authorization is active')
        }
        if (!sameIntent(authorization.intent, intent)) {
          throw new Error(
            'response vault: another authorization intent is active',
          )
        }
        if (
          authorization.status === 'relay_retry' ||
          authorization.status === 'redeeming'
        ) {
          authorization = await this.claimExecution(
            authorization,
            randomOpaque(),
            [authorization.status],
          )
          return this.relayAfterIframeCallback(authorization)
        }
      }
      authorization = await this.start(
        'iframe',
        intent,
        expectedGeneration,
      )
      try {
        const endpoints = await this.endpointRegistry()
        const iframeTimeout =
          this.config.iframeTimeoutMs ?? DEFAULT_IFRAME_TIMEOUT_MS
        const executionOwner = authorization.executionClaim?.owner
        if (!executionOwner) {
          throw new Error(
            'response vault: iframe execution owner is unavailable',
          )
        }
        authorization = await beginResponseVaultNavigation(
          authorization,
          Math.min(authorization.expiresAt, Date.now() + iframeTimeout),
        )
        await this.waitForCleanIframeCallback(
          authorization,
          endpoints.authorization,
        )
        authorization = await claimResponseVaultNavigation(
          authorization,
          executionOwner,
          'iframe',
          this.executionLeaseDuration(),
        )
        return this.relayAfterIframeCallback(authorization)
      } catch (error) {
        if (error instanceof ResponseVaultAuthorizationBusyError) {
          throw error
        }
        if (authorization.status === 'navigating') {
          const owner = authorization.navigationOwner
          if (!owner) {
            throw new Error(
              'response vault: iframe navigation owner is unavailable',
            )
          }
          try {
            const cancellation = await claimResponseVaultRejection(
              authorization,
              owner,
              ['navigating'],
              this.executionLeaseDuration(),
            )
            return await this.rejectAfterFailure(cancellation, error)
          } catch (claimError) {
            if (claimError instanceof ResponseVaultAuthorizationBusyError) {
              throw error
            }
            throw claimError
          }
        }
        return await this.rejectAfterFailure(authorization, error)
      }
    } catch (error) {
      if (authorization) {
        throw bindResponseVaultFailedInitialization(
          error,
          authorization,
        )
      }
      throw error
    }
  }
}
