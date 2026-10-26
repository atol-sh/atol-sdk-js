import {
  credentialGenerationSnapshot,
  currentCredentialAuthority,
  currentTabOwnerGeneration,
  rotateTabOwnerGeneration,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import { randomOpaque } from './response-vault-config'
import {
  REJECTION_CLAIM_STATUSES,
  ResponseVaultCleanupPendingError,
  ResponseVaultRejectionBlockedError,
} from './response-vault-contract'
import { ResponseVaultCustodyLayer } from './response-vault-custody'
import {
  ResponseVaultFailedInitializationModeMismatchError,
  type ResponseVaultFailedInitializationAuthority,
} from './response-vault-failed-initialization'
import {
  claimResponseVaultRejection,
  loadActiveResponseVaultCustody,
  ResponseVaultAuthorizationBusyError,
  type ResponseVaultCustody,
  type ResponseVaultExactGenerationSupersession,
} from './response-vault-storage'

const FAILED_INITIALIZATION_CANCELLATION = Symbol(
  'response-vault-failed-initialization-cancellation',
)
const FAILED_INITIALIZATION_RESTART = Symbol(
  'response-vault-failed-initialization-restart',
)

type LoginCancellationProvenance =
  | 'interactive_cancel'
  | 'failed_init_cancel'

function sameGeneration(
  left: CredentialGenerationSnapshot,
  right: CredentialGenerationSnapshot,
): boolean {
  return left.logout === right.logout && left.tabOwner === right.tabOwner
}

function sameBinding(
  left: ResponseVaultCustody['binding'],
  right: ResponseVaultCustody['binding'],
): boolean {
  return (
    left.issuer === right.issuer &&
    left.clientId === right.clientId &&
    left.redirectUri === right.redirectUri &&
    left.audience === right.audience &&
    left.scope === right.scope
  )
}

function retryableRejection(custody: ResponseVaultCustody): boolean {
  return custody.status === 'rejecting' || custody.status === 'reject_retry'
}

function provesCancellation(
  custody: ResponseVaultCustody,
  provenance: LoginCancellationProvenance,
): boolean {
  const expectedMode =
    provenance === 'interactive_cancel' ? 'interactive' : 'iframe'
  if ('mode' in custody) return custody.mode === expectedMode
  return (
    custody.sourceMode === expectedMode ||
    custody.rejectionProvenance === provenance
  )
}

/**
 * Exact, non-navigating cancellation for an abandoned interactive login.
 *
 * The server rejection claim is persisted before the tab generation rotates.
 * A failed caller can therefore resume only that durable rejection state; it
 * cannot use a stale generation to cancel a newer interactive authorization.
 * If rejection releases custody before rotation persists, the same instance
 * retains and verifies the old tab-owner fence before a retry can resolve.
 */
export abstract class ResponseVaultLoginCancellation
  extends ResponseVaultCustodyLayer {
  private pendingCancellationTabOwnerFence: string | undefined

  private completePendingTabOwnerRotation(): void {
    const pendingFence = this.pendingCancellationTabOwnerFence
    if (pendingFence === undefined) return
    if (currentTabOwnerGeneration(this.config) === pendingFence) {
      rotateTabOwnerGeneration(this.config)
    }
    if (currentTabOwnerGeneration(this.config) === pendingFence) {
      throw new Error(
        'response vault: cancellation tab-owner rotation was not persisted',
      )
    }
    this.pendingCancellationTabOwnerFence = undefined
  }

  async cancelLogin(onCleanupOwned?: () => void): Promise<void> {
    return this.cancelLoginWithProvenance(
      'interactive_cancel',
      onCleanupOwned,
    )
  }

  async [FAILED_INITIALIZATION_CANCELLATION](
    authority: ResponseVaultFailedInitializationAuthority,
    onCleanupOwned?: () => void,
  ): Promise<void> {
    return this.cancelFailedInitialization(
      authority,
      undefined,
      onCleanupOwned,
    )
  }

  async [FAILED_INITIALIZATION_RESTART](
    authority: ResponseVaultFailedInitializationAuthority,
    signedOutLogoutGeneration: string,
    onCleanupOwned?: () => void,
  ): Promise<void> {
    return this.cancelFailedInitialization(
      authority,
      signedOutLogoutGeneration,
      onCleanupOwned,
    )
  }

  private async finishSuccessfulCancellation(
    reference: ResponseVaultCustody['reference'],
    expectedGeneration: CredentialGenerationSnapshot,
    cleanupErrors: unknown[],
  ): Promise<void> {
    this.pendingCancellationTabOwnerFence = expectedGeneration.tabOwner
    try {
      this.completePendingTabOwnerRotation()
    } catch (error) {
      cleanupErrors.push(error)
    }
    if (this.lifecycle >= Number.MAX_SAFE_INTEGER) {
      cleanupErrors.push(
        new Error('response vault: lifecycle epoch is exhausted'),
      )
    } else {
      this.lifecycle++
    }
    this.discoveryFlight = undefined
    for (const controller of this.ownedRequests) controller.abort()
    this.ownedRequests.clear()
    const invalidation = new Error(
      'response vault: authorization lifecycle was superseded',
    )
    for (const cancel of this.ownedWaits) cancel(invalidation)
    this.ownedWaits.clear()
    try {
      this.clearActive(reference)
      if (this.activeReference() !== null) {
        throw new Error(
          'response vault: active authorization reference cleanup failed',
        )
      }
    } catch (error) {
      cleanupErrors.push(error)
    }
    this.clearPendingSettlement(reference)
    if (cleanupErrors.length > 0) {
      throw new ResponseVaultCleanupPendingError(undefined)
    }
  }

  private async cancelFailedInitialization(
    authority: ResponseVaultFailedInitializationAuthority,
    signedOutLogoutGeneration: string | undefined,
    onCleanupOwned?: () => void,
  ): Promise<void> {
    try {
      this.completePendingTabOwnerRotation()
    } catch {
      throw new ResponseVaultCleanupPendingError(undefined)
    }
    const lifecycleEpoch = this.lifecycle
    const expectedGeneration = credentialGenerationSnapshot(this.config)
    const restartAfterLogoutInvalidation =
      signedOutLogoutGeneration !== undefined
    const exactSupersession: ResponseVaultExactGenerationSupersession |
      undefined = restartAfterLogoutInvalidation
        ? {
            invalidatedGeneration: {
              ...authority.credentialGeneration,
            },
            signedOutLogoutGeneration,
            mode: authority.mode,
          }
        : undefined
    if (exactSupersession) {
      const currentAuthority = currentCredentialAuthority(this.config)
      if (
        !currentAuthority.signedOut ||
        currentAuthority.generation !== signedOutLogoutGeneration ||
        expectedGeneration.logout !== signedOutLogoutGeneration ||
        authority.credentialGeneration.logout === signedOutLogoutGeneration
      ) {
        throw new ResponseVaultAuthorizationBusyError()
      }
    }
    const provenance: LoginCancellationProvenance =
      authority.mode === 'interactive'
        ? 'interactive_cancel'
        : 'failed_init_cancel'
    const cleanupErrors: unknown[] = []
    let cleanupOwnershipMarked = false
    const markCleanupOwnership = () => {
      if (cleanupOwnershipMarked) return
      cleanupOwnershipMarked = true
      try {
        onCleanupOwned?.()
      } catch (error) {
        cleanupErrors.push(error)
      }
    }
    const pointer = this.activeReference()
    const active = await loadActiveResponseVaultCustody(
      this.config,
      lifecycleEpoch,
    )
    const custody = active.custody
    if (!custody) {
      if (
        restartAfterLogoutInvalidation &&
        !this.rejectedReferences.has(authority.reference.id)
      ) {
        throw new ResponseVaultCleanupPendingError(undefined)
      }
      if (
        restartAfterLogoutInvalidation &&
        pointer !== null &&
        pointer.id !== authority.reference.id
      ) {
        throw new ResponseVaultAuthorizationBusyError()
      }
      try {
        if (pointer) this.clearActive(pointer)
        if (this.activeReference() !== null) {
          throw new Error(
            'response vault: active authorization reference cleanup failed',
          )
        }
      } catch {
        throw new ResponseVaultCleanupPendingError(undefined)
      }
      return
    }
    if (
      (
        restartAfterLogoutInvalidation
          ? pointer !== null && pointer.id !== authority.reference.id
          : pointer === null || pointer.id !== authority.reference.id
      ) ||
      custody.reference.id !== authority.reference.id ||
      !sameBinding(custody.binding, this.config) ||
      !sameGeneration(
        custody.credentialGeneration,
        authority.credentialGeneration,
      ) ||
      (
        restartAfterLogoutInvalidation
          ? authority.credentialGeneration.logout ===
              expectedGeneration.logout
          : !sameGeneration(
              authority.credentialGeneration,
              expectedGeneration,
            )
      )
    ) {
      throw new ResponseVaultAuthorizationBusyError()
    }
    if (!provesCancellation(custody, provenance)) {
      throw new ResponseVaultFailedInitializationModeMismatchError()
    }

    if (!custody.transactionId) {
      if (!('dpopKey' in custody)) {
        throw new ResponseVaultCleanupPendingError(undefined)
      }
      await this.settlePreTransactionAuthorization(
        custody,
        randomOpaque(),
        restartAfterLogoutInvalidation,
        markCleanupOwnership,
        exactSupersession,
      )
      this.rejectedReferences.add(custody.reference.id)
      await this.finishSuccessfulCancellation(
        custody.reference,
        expectedGeneration,
        cleanupErrors,
      )
      return
    }

    const claimed = await claimResponseVaultRejection(
      custody,
      active.rejectionOwner ??
        ('dpopKey' in custody ? custody.navigationOwner : undefined) ??
        custody.executionClaim?.owner ??
        randomOpaque(),
      custody.status === 'reject_blocked'
        ? ['reject_blocked']
        : REJECTION_CLAIM_STATUSES,
      this.executionLeaseDuration(),
      !restartAfterLogoutInvalidation,
      true,
      restartAfterLogoutInvalidation,
      provenance,
      authority.mode,
      exactSupersession,
    )
    markCleanupOwnership()
    try {
      await this.rejectAuthorization(claimed)
    } catch (error) {
      if (!(error instanceof ResponseVaultRejectionBlockedError)) {
        throw error
      }
      const blocked = this.pendingRejectionCustody.get(
        claimed.reference.id,
      )
      if (!blocked) {
        throw new ResponseVaultCleanupPendingError(undefined)
      }
      await this.probeFailedInitializationTerminal(
        blocked,
        provenance,
        markCleanupOwnership,
        exactSupersession,
      )
      this.pendingRejectionCustody.delete(claimed.reference.id)
    }
    await this.finishSuccessfulCancellation(
      claimed.reference,
      restartAfterLogoutInvalidation
        ? authority.credentialGeneration
        : expectedGeneration,
      cleanupErrors,
    )
  }

  private async cancelLoginWithProvenance(
    provenance: LoginCancellationProvenance,
    onCleanupOwned?: () => void,
  ): Promise<void> {
    try {
      this.completePendingTabOwnerRotation()
    } catch {
      throw new ResponseVaultCleanupPendingError(undefined)
    }
    const lifecycleEpoch = this.lifecycle
    const expectedGeneration = credentialGenerationSnapshot(this.config)
    const pointer = this.activeReference()
    const active = await loadActiveResponseVaultCustody(
      this.config,
      lifecycleEpoch,
    )
    const custody = active.custody
    if (!custody) {
      try {
        if (pointer) {
          this.clearActive(pointer)
          if (this.activeReference() !== null) {
            throw new ResponseVaultCleanupPendingError(undefined)
          }
        }
      } catch {
        throw new ResponseVaultCleanupPendingError(undefined)
      }
      return
    }
    if (
      !sameBinding(custody.binding, this.config) ||
      !provesCancellation(custody, provenance) ||
      (
        !sameGeneration(custody.credentialGeneration, expectedGeneration) &&
        !retryableRejection(custody)
      ) ||
      (pointer !== null && pointer.id !== custody.reference.id)
    ) {
      throw new ResponseVaultAuthorizationBusyError()
    }
    if (!custody.transactionId) {
      throw new ResponseVaultCleanupPendingError(undefined)
    }

    const claimed = await claimResponseVaultRejection(
      custody,
      active.rejectionOwner ??
        ('dpopKey' in custody ? custody.navigationOwner : undefined) ??
        custody.executionClaim?.owner ??
        randomOpaque(),
      REJECTION_CLAIM_STATUSES,
      this.executionLeaseDuration(),
      false,
      false,
      !sameGeneration(custody.credentialGeneration, expectedGeneration),
      provenance,
    )
    const cleanupErrors: unknown[] = []
    this.pendingCancellationTabOwnerFence = expectedGeneration.tabOwner
    try {
      onCleanupOwned?.()
    } catch (error) {
      cleanupErrors.push(error)
    }
    try {
      this.completePendingTabOwnerRotation()
    } catch (error) {
      cleanupErrors.push(error)
    }
    if (this.lifecycle >= Number.MAX_SAFE_INTEGER) {
      cleanupErrors.push(
        new Error('response vault: lifecycle epoch is exhausted'),
      )
    } else {
      this.lifecycle++
    }
    this.discoveryFlight = undefined
    for (const controller of this.ownedRequests) controller.abort()
    this.ownedRequests.clear()
    const invalidation = new Error(
      'response vault: authorization lifecycle was superseded',
    )
    for (const cancel of this.ownedWaits) cancel(invalidation)
    this.ownedWaits.clear()
    try {
      this.clearActive(claimed.reference)
      if (this.activeReference() !== null) {
        throw new Error(
          'response vault: active authorization reference cleanup failed',
        )
      }
    } catch (error) {
      cleanupErrors.push(error)
    }
    this.clearPendingSettlement(claimed.reference)

    try {
      await this.rejectAuthorization(claimed)
    } catch (error) {
      cleanupErrors.push(error)
    }
    if (cleanupErrors.length > 0) {
      throw new ResponseVaultCleanupPendingError(undefined)
    }
  }
}

/**
 * Internal recovery for the exact authorization that caused browser
 * initialization to reject. Browser auth must provide the hidden failure-time
 * reference, mode, and generation; ordinary public cancellation remains
 * interactive-only.
 */
export function cancelResponseVaultFailedInitialization(
  vault: ResponseVaultLoginCancellation,
  authority: ResponseVaultFailedInitializationAuthority,
  onCleanupOwned?: () => void,
): Promise<void> {
  return vault[FAILED_INITIALIZATION_CANCELLATION](
    authority,
    onCleanupOwned,
  )
}

/**
 * Internal restart settlement for the exact authorization that caused
 * browser initialization to reject. The caller must first invalidate the
 * authority's origin-wide logout generation. A missing same-tab pointer is
 * then permitted, but the durable reference, binding, mode, generation, and
 * active slot must all still match before rejection can be claimed.
 */
export function restartResponseVaultFailedInitialization(
  vault: ResponseVaultLoginCancellation,
  authority: ResponseVaultFailedInitializationAuthority,
  signedOutLogoutGeneration: string,
  onCleanupOwned?: () => void,
): Promise<void> {
  return vault[FAILED_INITIALIZATION_RESTART](
    authority,
    signedOutLogoutGeneration,
    onCleanupOwned,
  )
}
