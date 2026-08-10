import {
  assertCredentialGenerationSnapshot,
  CredentialGenerationInvalidatedError,
  CredentialGenerationSupersededError,
  credentialGenerationSnapshot,
  rotateLogoutGeneration,
  rotateTabOwnerGeneration,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import { randomOpaque } from './response-vault-config'
import {
  CANONICAL_OPAQUE,
  REJECTION_CLAIM_STATUSES,
  RESPONSE_VAULT_PROTOCOL_VERSION,
  ResponseVaultAuthorizationBindingMismatchError,
  ResponseVaultAuthorizationInvalidatedError,
  ResponseVaultAuthenticatedTerminalError,
  ResponseVaultCleanupPendingError,
  ResponseVaultGrantRejectedError,
  ResponseVaultRejectionBlockedError,
  ResponseVaultRejectionPendingError,
  aggregateCleanupError,
} from './response-vault-contract'
import { ResponseVaultRejection } from './response-vault-rejection'
import {
  claimResponseVaultRejection,
  discardResponseVaultAuthorization,
  loadActiveResponseVaultCustody,
  loadResponseVaultCompensations,
  loadResponseVaultLifecycleCancellations,
  loadResponseVaultTerminalProbes,
  releaseResponseVaultExecution,
  responseVaultCustodyReleased,
  ResponseVaultAuthorizationBusyError,
  ResponseVaultExecutionBusyError,
  type ResponseVaultAuthorization,
  type ResponseVaultCancellation,
  type ResponseVaultCustody,
  type ResponseVaultReference,
} from './response-vault-storage'

function closedCustodyError(error: unknown): Error {
  try {
    if (
      error instanceof CredentialGenerationInvalidatedError ||
      error instanceof CredentialGenerationSupersededError
    ) {
      return new ResponseVaultAuthorizationInvalidatedError()
    }
    if (error instanceof ResponseVaultExecutionBusyError) {
      return new ResponseVaultExecutionBusyError()
    }
    if (error instanceof ResponseVaultAuthorizationBusyError) {
      return new ResponseVaultAuthorizationBusyError()
    }
    if (error instanceof ResponseVaultAuthorizationBindingMismatchError) {
      return new ResponseVaultAuthorizationBindingMismatchError()
    }
    if (error instanceof ResponseVaultAuthorizationInvalidatedError) {
      return new ResponseVaultAuthorizationInvalidatedError()
    }
    if (error instanceof ResponseVaultCleanupPendingError) {
      return new ResponseVaultCleanupPendingError(undefined)
    }
    if (error instanceof ResponseVaultGrantRejectedError) {
      return new ResponseVaultGrantRejectedError()
    }
    if (error instanceof ResponseVaultRejectionBlockedError) {
      return new ResponseVaultRejectionBlockedError(undefined)
    }
    if (error instanceof ResponseVaultRejectionPendingError) {
      return new ResponseVaultRejectionPendingError(undefined)
    }
  } catch {
    // Arbitrary caught values may be hostile proxies. Classification must
    // never inspect or retain them beyond this closed boundary.
  }
  return new ResponseVaultCleanupPendingError(undefined)
}

export abstract class ResponseVaultCustodyLayer extends ResponseVaultRejection {
  invalidateLifecycle(rotateLogout = false): Promise<void> {
    return this.invalidateLifecycleWithPolicy(rotateLogout, rotateLogout)
  }

  /**
   * Retry application-wide logout custody for an already durable signed-out
   * authority. This does not rotate the shared authority again because another
   * tab may have explicitly started a newer login before cleanup runs.
   */
  invalidateSignedOutLifecycle(): Promise<void> {
    return this.invalidateLifecycleWithPolicy(false, true)
  }

  private invalidateLifecycleWithPolicy(
    rotateLogout: boolean,
    applicationCleanup: boolean,
  ): Promise<void> {
    const previousLifecycle = this.lifecycle
    let firstError: unknown
    let storage: Storage | undefined
    let reference: ResponseVaultReference | null = null
    let previousGeneration: CredentialGenerationSnapshot | undefined

    try {
      storage = this.storage()
      const rawReference = storage.getItem(this.pointerKey)
      if (rawReference !== null) {
        if (CANONICAL_OPAQUE.test(rawReference)) {
          reference = {
            version: RESPONSE_VAULT_PROTOCOL_VERSION,
            id: rawReference,
          }
        } else {
          firstError = new Error(
            'response vault: active authorization reference is corrupt',
          )
        }
      }
    } catch (error) {
      firstError = error
    }
    try {
      previousGeneration = credentialGenerationSnapshot(this.config)
    } catch (error) {
      firstError ??= error
    }
    if (rotateLogout) {
      try {
        rotateLogoutGeneration(this.config)
      } catch (error) {
        firstError ??= error
      }
    }
    try {
      rotateTabOwnerGeneration(this.config)
    } catch (error) {
      firstError ??= error
    }
    if (this.lifecycle >= Number.MAX_SAFE_INTEGER) {
      firstError ??= new Error('response vault: lifecycle epoch is exhausted')
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
    if (storage) {
      try {
        storage.removeItem(this.pointerKey)
      } catch (error) {
        firstError ??= error
      }
    }
    this.clearPendingSettlement(reference ?? undefined)

    return (async () => {
      const cleanupErrors: unknown[] = []
      let active: ResponseVaultCustody | null = null
      try {
        active = (
          await loadActiveResponseVaultCustody(this.config, previousLifecycle)
        ).custody
      } catch (error) {
        cleanupErrors.push(error)
      }
      let cancellations: ResponseVaultCancellation[] = []
      let cancellationBatch:
        | Awaited<ReturnType<typeof loadResponseVaultLifecycleCancellations>>
        | undefined
      try {
        cancellationBatch = await loadResponseVaultLifecycleCancellations(
          this.config,
          previousLifecycle,
          applicationCleanup ? 'application' : 'exact',
        )
        cancellations = cancellationBatch.cancellations
        cleanupErrors.push(...cancellationBatch.errors)
        if (cancellationBatch.hasMore) {
          cleanupErrors.push(
            new ResponseVaultCleanupPendingError(
              new Error(
                'response vault: lifecycle cleanup inventory remains pending',
              ),
            ),
          )
        }
      } catch (error) {
        cleanupErrors.push(error)
      }
      const candidates: ResponseVaultCustody[] = active
        ? [active, ...cancellations]
        : cancellations
      const seen = new Set<string>()
      let cancellationBatchSucceeded =
        cancellationBatch !== undefined && cancellationBatch.errors.length === 0
      for (const custody of candidates) {
        if (seen.has(custody.reference.id)) continue
        seen.add(custody.reference.id)
        const sameApplication =
          custody.binding.issuer === this.config.issuer &&
          custody.binding.clientId === this.config.clientId &&
          new URL(custody.binding.redirectUri).origin === this.clientOrigin
        const ownsAuthorization = applicationCleanup
          ? sameApplication
          : previousGeneration !== undefined &&
            custody.binding.issuer === this.config.issuer &&
            custody.binding.clientId === this.config.clientId &&
            custody.binding.redirectUri === this.config.redirectUri &&
            custody.binding.audience === this.config.audience &&
            custody.binding.scope === this.config.scope &&
            custody.credentialGeneration.tabOwner ===
              previousGeneration.tabOwner
        if (!ownsAuthorization) continue
        try {
          if (custody.transactionId) {
            const claimed = await claimResponseVaultRejection(
              custody,
              custody.executionClaim?.owner ?? randomOpaque(),
              REJECTION_CLAIM_STATUSES,
              this.executionLeaseDuration(),
              false,
              false,
              true,
            )
            await this.rejectAuthorization(claimed)
          } else if ('dpopKey' in custody) {
            // A pre-transaction request may already have committed its
            // bootstrap response even when this runtime only observed a
            // transport failure. Keep the exact capabilities so a later
            // terminal-only probe can fence or classify that attempt.
            continue
          } else {
            cancellationBatchSucceeded = false
            cleanupErrors.push(
              new Error('response vault: cancellation binding is incomplete'),
            )
          }
        } catch (error) {
          try {
            if (await responseVaultCustodyReleased(custody)) {
              continue
            }
          } catch (verificationError) {
            cleanupErrors.push(verificationError)
          }
          cancellationBatchSucceeded = false
          cleanupErrors.push(error)
        }
      }
      if (cancellationBatchSucceeded && cancellationBatch) {
        try {
          cancellationBatch.commit()
        } catch (error) {
          cleanupErrors.push(error)
        }
      }
      if (firstError !== undefined) {
        cleanupErrors.unshift(firstError)
      }
      const cleanupError = aggregateCleanupError(cleanupErrors)
      if (cleanupError !== undefined) throw cleanupError
    })()
  }

  private async settleAbandonedCompensations(
    lifecycleEpoch: number,
    activeReferenceId?: string,
  ): Promise<void> {
    const currentGeneration = credentialGenerationSnapshot(this.config)
    const batch = await loadResponseVaultCompensations(
      this.config,
      lifecycleEpoch,
    )
    const cleanupErrors = [...batch.errors]
    let compensationBatchSucceeded = batch.errors.length === 0
    let compensationBusy = false
    if (batch.hasMore) {
      cleanupErrors.push(
        new ResponseVaultCleanupPendingError(
          new Error('response vault: compensation inventory remains pending'),
        ),
      )
    }
    for (const cancellation of batch.cancellations) {
      if (cancellation.reference.id === activeReferenceId) continue
      const owned =
        cancellation.binding.issuer === this.config.issuer &&
        cancellation.binding.clientId === this.config.clientId &&
        cancellation.binding.redirectUri === this.config.redirectUri &&
        cancellation.binding.audience === this.config.audience &&
        cancellation.binding.scope === this.config.scope &&
        cancellation.credentialGeneration.tabOwner ===
          currentGeneration.tabOwner
      if (!owned || cancellation.status === 'reject_blocked') continue
      try {
        const claimed = await claimResponseVaultRejection(
          cancellation,
          cancellation.executionClaim?.owner ?? randomOpaque(),
          REJECTION_CLAIM_STATUSES,
          this.executionLeaseDuration(),
          true,
          false,
        )
        await this.rejectAuthorization(claimed)
      } catch (error) {
        compensationBatchSucceeded = false
        if (error instanceof ResponseVaultAuthorizationBusyError) {
          compensationBusy = true
        } else {
          cleanupErrors.push(error)
        }
      }
    }
    if (compensationBatchSucceeded) {
      try {
        batch.commit()
      } catch (error) {
        cleanupErrors.push(error)
      }
    } else if (compensationBusy || cleanupErrors.length === 0) {
      cleanupErrors.push(
        new ResponseVaultCleanupPendingError(
          new Error('response vault: compensation batch remains pending'),
        ),
      )
    }
    const probes = await loadResponseVaultTerminalProbes(
      this.config,
      lifecycleEpoch,
    )
    cleanupErrors.push(...probes.errors)
    let probeBatchSucceeded = probes.errors.length === 0
    let probeBusy = false
    if (probes.hasMore) {
      cleanupErrors.push(
        new ResponseVaultCleanupPendingError(
          new Error('response vault: terminal probe inventory remains pending'),
        ),
      )
    }
    for (const cancellation of probes.cancellations) {
      if (cancellation.reference.id === activeReferenceId) continue
      const owned =
        cancellation.binding.issuer === this.config.issuer &&
        cancellation.binding.clientId === this.config.clientId &&
        cancellation.binding.redirectUri === this.config.redirectUri &&
        cancellation.binding.audience === this.config.audience &&
        cancellation.binding.scope === this.config.scope &&
        cancellation.credentialGeneration.tabOwner ===
          currentGeneration.tabOwner
      if (!owned) continue
      try {
        await this.probePublishedTerminal(cancellation)
      } catch (error) {
        probeBatchSucceeded = false
        if (error instanceof ResponseVaultAuthorizationBusyError) {
          probeBusy = true
        } else {
          cleanupErrors.push(error)
        }
      }
    }
    if (probeBatchSucceeded) {
      try {
        probes.commit()
      } catch (error) {
        cleanupErrors.push(error)
      }
    } else if (probeBusy || cleanupErrors.length === 0) {
      cleanupErrors.push(
        new ResponseVaultCleanupPendingError(
          new Error('response vault: terminal probe batch remains pending'),
        ),
      )
    }
    const cleanupError = aggregateCleanupError(cleanupErrors)
    if (cleanupError !== undefined) throw cleanupError
  }

  protected async activeAuthorization(
    lifecycleEpoch: number,
  ): Promise<ResponseVaultAuthorization | null> {
    try {
      return await this.resolveActiveAuthorization(lifecycleEpoch)
    } catch (error) {
      throw closedCustodyError(error)
    }
  }

  private async resolveActiveAuthorization(
    lifecycleEpoch: number,
  ): Promise<ResponseVaultAuthorization | null> {
    this.assertLifecycle(lifecycleEpoch)
    const active = await loadActiveResponseVaultCustody(
      this.config,
      lifecycleEpoch,
    )
    const authorization = active.custody
    let abandonedCleanupError: unknown
    try {
      await this.settleAbandonedCompensations(
        lifecycleEpoch,
        authorization?.reference.id,
      )
    } catch (error) {
      abandonedCleanupError = error
    }
    const failAfterCleanup = (error: unknown): never => {
      if (abandonedCleanupError !== undefined) {
        // Cleanup authority takes precedence once it has failed. Neither the
        // primary failure nor the caught cleanup value may reach callers.
        throw new ResponseVaultCleanupPendingError(undefined)
      }
      throw closedCustodyError(error)
    }
    const runWithCleanupPrecedence = async <T>(
      operation: () => Promise<T>,
    ): Promise<T> => {
      try {
        return await operation()
      } catch (error) {
        if (abandonedCleanupError !== undefined) {
          throw new ResponseVaultCleanupPendingError(undefined)
        }
        throw error
      }
    }
    let pointer: ResponseVaultReference | null = null
    try {
      pointer = this.activeReference()
    } catch {
      this.storage().removeItem(this.pointerKey)
    }
    if (!authorization) {
      if (pointer) this.clearActive(pointer)
      if (abandonedCleanupError !== undefined) {
        throw new ResponseVaultCleanupPendingError(undefined)
      }
      return null
    }
    if (pointer && pointer.id !== authorization.reference.id) {
      this.clearActive(pointer)
    }
    const bindingMatches =
      authorization.binding.issuer === this.config.issuer &&
      authorization.binding.clientId === this.config.clientId &&
      authorization.binding.redirectUri === this.config.redirectUri &&
      authorization.binding.audience === this.config.audience &&
      authorization.binding.scope === this.config.scope
    const currentGeneration = credentialGenerationSnapshot(this.config)
    const rejectionOwner =
      authorization.executionClaim?.owner ??
      active.rejectionOwner ??
      randomOpaque()
    if (
      !bindingMatches ||
      authorization.credentialGeneration.tabOwner !== currentGeneration.tabOwner
    ) {
      failAfterCleanup(new ResponseVaultAuthorizationBusyError())
    }
    try {
      assertCredentialGenerationSnapshot(
        this.config,
        authorization.credentialGeneration,
      )
    } catch (error) {
      if (authorization.transactionId) {
        const claimed = await runWithCleanupPrecedence(() =>
          claimResponseVaultRejection(
            authorization,
            rejectionOwner,
            REJECTION_CLAIM_STATUSES,
            this.executionLeaseDuration(),
            false,
            false,
            true,
          ),
        )
        await runWithCleanupPrecedence(() =>
          this.rejectAuthorization(claimed),
        )
      } else if ('dpopKey' in authorization) {
        try {
          await this.settlePreTransactionAuthorization(
            authorization,
            randomOpaque(),
            true,
          )
        } catch (cleanupError) {
          failAfterCleanup(cleanupError)
        }
      } else {
        failAfterCleanup(
          new Error('response vault: cancellation binding is incomplete'),
        )
      }
      failAfterCleanup(error)
    }
    if (active.grantError !== undefined) {
      const claimed = await runWithCleanupPrecedence(() =>
        claimResponseVaultRejection(
          authorization,
          rejectionOwner,
          REJECTION_CLAIM_STATUSES,
          this.executionLeaseDuration(),
          true,
          false,
        ),
      )
      await runWithCleanupPrecedence(() =>
        this.rejectAuthorization(claimed),
      )
      failAfterCleanup(active.grantError)
    }
    if (!('dpopKey' in authorization)) {
      if (authorization.status === 'reject_blocked') {
        failAfterCleanup(
          new ResponseVaultRejectionBlockedError(
            new Error('response vault: rejection remains blocked'),
          ),
        )
      }
      const claimed = await runWithCleanupPrecedence(() =>
        claimResponseVaultRejection(
          authorization,
          rejectionOwner,
          REJECTION_CLAIM_STATUSES,
          this.executionLeaseDuration(),
          true,
          false,
        ),
      )
      await runWithCleanupPrecedence(() =>
        this.rejectAuthorization(claimed),
      )
      return failAfterCleanup(new ResponseVaultGrantRejectedError())
    }
    if (abandonedCleanupError !== undefined) {
      throw new ResponseVaultCleanupPendingError(undefined)
    }
    this.setActive(authorization.reference)
    return authorization
  }

  private async settlePreTransactionAuthorization(
    authorization: ResponseVaultAuthorization,
    owner: string,
    supersedeInvalidatedGeneration: boolean,
  ): Promise<void> {
    const claimed = await this.claimExecution(
      authorization,
      owner,
      ['prepared', 'par_pending'],
      0,
      false,
      true,
      supersedeInvalidatedGeneration,
    )
    try {
      await this.bootstrapClient(claimed, 'terminal_only')
      throw new Error(
        'response vault: terminal bootstrap classification returned',
      )
    } catch (error) {
      if (error instanceof ResponseVaultAuthenticatedTerminalError) {
        this.clearActive(claimed.reference)
        await discardResponseVaultAuthorization(claimed)
        return
      }
      await releaseResponseVaultExecution(claimed, true, false)
      throw error
    }
  }
}
