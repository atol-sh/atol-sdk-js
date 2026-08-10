import {
  credentialGenerationSnapshot,
  currentTabOwnerGeneration,
  rotateTabOwnerGeneration,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import { randomOpaque } from './response-vault-config'
import {
  REJECTION_CLAIM_STATUSES,
  ResponseVaultCleanupPendingError,
} from './response-vault-contract'
import { ResponseVaultCustodyLayer } from './response-vault-custody'
import {
  claimResponseVaultRejection,
  loadActiveResponseVaultCustody,
  ResponseVaultAuthorizationBusyError,
  type ResponseVaultCustody,
} from './response-vault-storage'

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

function provesInteractiveCancellation(
  custody: ResponseVaultCustody,
): boolean {
  if ('mode' in custody) return custody.mode === 'interactive'
  return (
    custody.sourceMode === 'interactive' ||
    custody.rejectionProvenance === 'interactive_cancel'
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
      !provesInteractiveCancellation(custody) ||
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
      'interactive_cancel',
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
