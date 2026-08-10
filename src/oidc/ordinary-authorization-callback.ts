import type { UserManager } from 'oidc-client-ts'
import {
  restoreDPoPKeyManager,
  type DPoPKeyManager,
} from '../dpop/dpop'
import {
  assertCredentialGenerationSnapshot,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import {
  type AuthorizationCodeCallback,
  type AuthorizationCodeResponseState,
} from './oidc'
import { OrdinaryAuthorizationCleanupController } from './ordinary-authorization-cleanup'
import { acquireOrdinaryAuthorizationCallbackLock } from './ordinary-authorization-lock'
import {
  OrdinaryAuthorizationPendingError,
  authorizationCodeSHA256,
  ordinaryAuthorizationSlotKey,
  parseOrdinaryAuthorizationIntent,
  type OrdinaryAuthorizationBinding,
  type OrdinaryAuthorizationCallbackCustody,
  type OrdinaryAuthorizationCallbackRecovery,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  claimOrdinaryAuthorizationRecord,
  loadOrdinaryAuthorizationRecord,
  markOrdinaryAuthorizationCodeIssued,
  ordinaryAuthorizationPointerStorage,
  parseOrdinaryAuthorizationPointer,
  releaseOrdinaryAuthorizationClaim,
  requireOrdinaryAuthorizationRejection,
  validateOrdinaryAuthorizationEnvelopeInventory,
} from './ordinary-authorization-storage'
import {
  assertOrdinaryAuthorizationCallbackMatches,
  assertOrdinaryAuthorizationRecord,
  assertOrdinaryAuthorizationRecordState,
} from './ordinary-authorization-validation'
import { parseUniqueJSONObject } from './strict-json'

function callbackFromRecord(
  record: OrdinaryAuthorizationRecord,
): AuthorizationCodeCallback {
  if (record.callbackCode === null) {
    throw new Error(
      'ordinary browser authorization: recovery code is missing',
    )
  }
  const state = parseUniqueJSONObject(
    record.stateStorage,
    32 * 1024,
  )
  const parameters = new URLSearchParams(record.form)
  const codeVerifier = state.code_verifier
  const nonce = parameters.get('nonce')
  if (
    typeof codeVerifier !== 'string' ||
    nonce === null
  ) {
    throw new Error(
      'ordinary browser authorization: recovery state is invalid',
    )
  }
  const returnTo =
    parseOrdinaryAuthorizationIntent(record.intent).returnTo ??
    undefined
  return {
    code: record.callbackCode,
    codeVerifier,
    redirectUri: record.redirectUri,
    nonce,
    returnTo,
    credentialGeneration: {
      ...record.credentialGeneration,
    },
  }
}

export class OrdinaryAuthorizationCallbackController {
  private readonly cleanup: OrdinaryAuthorizationCleanupController

  constructor(
    manager: UserManager,
    private readonly binding: OrdinaryAuthorizationBinding,
    private readonly storageKey: string,
  ) {
    this.cleanup = new OrdinaryAuthorizationCleanupController(
      manager,
      binding,
      storageKey,
    )
  }

  async claimCallback(
    callback: AuthorizationCodeResponseState,
    generation: CredentialGenerationSnapshot,
  ): Promise<OrdinaryAuthorizationCallbackCustody> {
    assertCredentialGenerationSnapshot(this.binding, generation)
    const pointer = parseOrdinaryAuthorizationPointer(
      ordinaryAuthorizationPointerStorage().getItem(this.storageKey),
    )
    if (
      !pointer ||
      pointer.stateId !== callback.stateId ||
      pointer.tabOwnerGeneration !== generation.tabOwner
    ) {
      throw new Error(
        'ordinary browser authorization: callback pointer mismatch',
      )
    }
    const record = await loadOrdinaryAuthorizationRecord(
      ordinaryAuthorizationSlotKey(
        this.binding,
        generation.tabOwner,
      ),
    )
    if (!record) {
      throw new Error(
        'ordinary browser authorization: callback custody is missing',
      )
    }
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      record.intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    if (record.cleanupStarted) {
      await this.cleanup.finishCleanup(record)
      throw new Error(
        'ordinary browser authorization: callback custody was already settled',
      )
    }
    if (record.rejectionRequired) {
      await this.cleanup.rejectAndCleanup(record)
      throw new Error(
        'ordinary browser authorization: callback custody was rejected',
      )
    }
    assertOrdinaryAuthorizationCallbackMatches(
      record,
      callback,
      generation,
    )
    const processLock =
      await acquireOrdinaryAuthorizationCallbackLock(
        record.slotKey,
      )
    let claimed: OrdinaryAuthorizationRecord
    try {
      claimed = await claimOrdinaryAuthorizationRecord(
        record,
        callback.code ?? null,
        callback.code === undefined
          ? null
          : await authorizationCodeSHA256(callback.code),
      )
    } catch (error) {
      await processLock.release()
      throw error
    }
    let dpopKey: DPoPKeyManager | null = null
    if (record.keys !== null && record.dpopJkt !== null) {
      try {
        dpopKey = restoreDPoPKeyManager(record.keys)
        if ((await dpopKey.thumbprint()) !== record.dpopJkt) {
          throw new Error(
            'ordinary browser authorization: stored DPoP key mismatch',
          )
        }
      } catch (error) {
        try {
          await this.cleanup.rejectAndCleanup(claimed)
        } finally {
          claimed.callbackCode = null
          claimed.callbackCodeHash = null
          await processLock.release()
        }
        throw error
      }
    }
    let settled = false
    const compensationRequired = claimed.compensationRequired
    const settle = async (): Promise<void> => {
      if (settled) {
        throw new Error(
          'ordinary browser authorization: callback custody is already settled',
        )
      }
      try {
        await this.settleCallback(claimed)
      } finally {
        claimed.callbackCode = null
        claimed.callbackCodeHash = null
        settled = true
        await processLock.release()
      }
    }
    const release = async (): Promise<void> => {
      if (settled) {
        throw new Error(
          'ordinary browser authorization: callback custody is already settled',
        )
      }
      try {
        await releaseOrdinaryAuthorizationClaim(claimed)
      } finally {
        claimed.callbackCode = null
        claimed.callbackCodeHash = null
        settled = true
        await processLock.release()
      }
    }
    return {
      dpopKey,
      compensationRequired,
      markCodeIssued: async () => {
        if (settled || claimed.compensationRequired) {
          throw new Error(
            'ordinary browser authorization: code issuance phase is invalid',
          )
        }
        try {
          claimed = await markOrdinaryAuthorizationCodeIssued(claimed)
        } catch (error) {
          claimed.callbackCode = null
          claimed.callbackCodeHash = null
          settled = true
          await processLock.release()
          throw error
        }
      },
      complete: settle,
      discard: async () => {
        if (settled) {
          throw new Error(
            'ordinary browser authorization: callback custody is already settled',
          )
        }
        try {
          if (claimed.callbackCode !== null) {
            await this.cleanup.rejectAndCleanup(claimed)
          } else {
            await this.cleanup.terminalOnlyAndCleanup(claimed)
          }
        } finally {
          claimed.callbackCode = null
          claimed.callbackCodeHash = null
          settled = true
          await processLock.release()
        }
      },
      release,
    }
  }

  async claimPendingCallback(
    generation: CredentialGenerationSnapshot,
  ): Promise<OrdinaryAuthorizationCallbackRecovery | null> {
    assertCredentialGenerationSnapshot(this.binding, generation)
    await validateOrdinaryAuthorizationEnvelopeInventory()
    const record = await loadOrdinaryAuthorizationRecord(
      ordinaryAuthorizationSlotKey(
        this.binding,
        generation.tabOwner,
      ),
    )
    if (!record) return null
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      record.intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    if (record.cleanupStarted) {
      await this.cleanup.finishCleanup(record)
      return null
    }
    if (record.rejectionRequired) {
      await this.cleanup.rejectAndCleanup(record)
      return null
    }
    if (record.callbackCode === null) return null
    const callback = callbackFromRecord(record)
    const responseState: AuthorizationCodeResponseState = {
      ...callback,
      stateId: record.stateId,
      stateStorage: record.stateStorage,
      stateCreatedAt: record.stateCreatedAt,
      codeChallenge:
        new URLSearchParams(record.form).get(
          'code_challenge',
        ) as string,
    }
    return {
      callback,
      custody: await this.claimCallback(
        responseState,
        generation,
      ),
    }
  }

  async discardCallback(
    callback: AuthorizationCodeResponseState,
    generation: CredentialGenerationSnapshot,
  ): Promise<void> {
    let record = await loadOrdinaryAuthorizationRecord(
      ordinaryAuthorizationSlotKey(
        this.binding,
        generation.tabOwner,
      ),
    )
    if (!record) return
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      record.intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    assertOrdinaryAuthorizationCallbackMatches(
      record,
      callback,
      generation,
    )
    if (callback.code !== undefined) {
      record = await this.rejectCallbackCode(
        record,
        callback.code,
      )
    }
    if (callback.code !== undefined) {
      await this.cleanup.rejectAndCleanup(record)
      return
    }
    if (!callback.error) {
      throw new OrdinaryAuthorizationPendingError()
    }
    await this.cleanup.terminalOnlyAndCleanupWithoutPointer(record)
  }

  async finishPendingCleanup(
    generation: CredentialGenerationSnapshot,
  ): Promise<boolean> {
    assertCredentialGenerationSnapshot(this.binding, generation)
    const record = await loadOrdinaryAuthorizationRecord(
      ordinaryAuthorizationSlotKey(
        this.binding,
        generation.tabOwner,
      ),
    )
    if (!record || !record.cleanupStarted) return false
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      record.intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    await this.cleanup.finishCleanup(record)
    return true
  }

  async invalidateCurrent(
    generation: CredentialGenerationSnapshot,
  ): Promise<void> {
    return this.cleanup.invalidateCurrent(generation)
  }

  invalidateSignedOutLifecycle(): Promise<void> {
    return this.cleanup.invalidateSignedOutLifecycle()
  }

  private async rejectCallbackCode(
    record: OrdinaryAuthorizationRecord,
    code: string,
  ): Promise<OrdinaryAuthorizationRecord> {
    const processLock =
      await acquireOrdinaryAuthorizationCallbackLock(
        record.slotKey,
      )
    let claimed: OrdinaryAuthorizationRecord | null = null
    try {
      claimed = await claimOrdinaryAuthorizationRecord(
        record,
        code,
        await authorizationCodeSHA256(code),
      )
      try {
        return await requireOrdinaryAuthorizationRejection(claimed)
      } catch (error) {
        await releaseOrdinaryAuthorizationClaim(claimed)
        throw error
      }
    } finally {
      if (claimed !== null) {
        claimed.callbackCode = null
        claimed.callbackCodeHash = null
      }
      await processLock.release()
    }
  }

  async cleanupRecord(
    record: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    return this.cleanup.cleanupRecord(record)
  }

  async cleanupRecordWithoutPointer(
    record: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    return this.cleanup.cleanupPreparedRecordWithoutPointer(record)
  }

  async finishCleanup(
    cleaning: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    return this.cleanup.finishCleanup(cleaning)
  }

  private async settleCallback(
    claimed: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    await this.cleanup.cleanupRecord(claimed)
  }
}
