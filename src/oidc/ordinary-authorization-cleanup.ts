import type { UserManager } from 'oidc-client-ts'
import {
  assertCredentialGenerationSnapshot,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import { removeAuthorizationRequestState } from './oidc'
import {
  ordinaryAuthorizationPointerKey,
  ordinaryAuthorizationSlotKey,
  OrdinaryAuthorizationPendingError,
  type OrdinaryAuthorizationBinding,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import { cancelSubmittedOrdinaryAuthorization } from './ordinary-authorization-pre-navigation'
import { settleOrdinaryAuthorization } from './ordinary-authorization-settlement'
import {
  deleteOrdinaryAuthorizationRecordRevision,
  loadOrdinaryAuthorizationInventory,
  loadOrdinaryAuthorizationRecord,
  ordinaryAuthorizationPointerStorage,
  parseOrdinaryAuthorizationPointer,
  requireOrdinaryAuthorizationRejection,
  startOrdinaryAuthorizationCleanup,
} from './ordinary-authorization-storage'
import {
  assertOrdinaryAuthorizationRecord,
  assertOrdinaryAuthorizationRecordState,
  classifyOrdinaryAuthorizationRecordEnvelope,
} from './ordinary-authorization-validation'

export class OrdinaryAuthorizationCleanupController {
  constructor(
    private readonly manager: UserManager,
    private readonly binding: OrdinaryAuthorizationBinding,
    private readonly storageKey: string,
  ) {}

  private assertExactPointer(record: OrdinaryAuthorizationRecord): void {
    const storageKey = ordinaryAuthorizationPointerKey(record)
    const pointer = parseOrdinaryAuthorizationPointer(
      ordinaryAuthorizationPointerStorage().getItem(storageKey),
    )
    if (
      !pointer ||
      pointer.stateId !== record.stateId ||
      pointer.tabOwnerGeneration !== record.credentialGeneration.tabOwner
    ) {
      throw new Error(
        'ordinary browser authorization: cleanup pointer mismatch',
      )
    }
  }

  async cleanupRecord(record: OrdinaryAuthorizationRecord): Promise<void> {
    this.assertExactPointer(record)
    await this.startAndFinishCleanup(record)
  }

  async cleanupPreparedRecordWithoutPointer(
    record: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    if (record.parPhase !== 'prepared' || record.rejectionRequired) {
      throw new Error(
        'ordinary browser authorization: prepared cleanup phase is invalid',
      )
    }
    await this.startAndFinishCleanup(record)
  }

  private async startAndFinishCleanup(
    record: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    await this.finishCleanup(await startOrdinaryAuthorizationCleanup(record))
  }

  async finishCleanup(cleaning: OrdinaryAuthorizationRecord): Promise<void> {
    if (!cleaning.cleanupStarted) {
      throw new Error(
        'ordinary browser authorization: cleanup phase is invalid',
      )
    }
    await removeAuthorizationRequestState(
      this.manager,
      cleaning.stateId,
      cleaning.stateStorage,
    )
    const storageKey = ordinaryAuthorizationPointerKey(cleaning)
    const pointer = parseOrdinaryAuthorizationPointer(
      ordinaryAuthorizationPointerStorage().getItem(storageKey),
    )
    if (
      pointer !== null &&
      pointer.stateId === cleaning.stateId &&
      pointer.tabOwnerGeneration === cleaning.credentialGeneration.tabOwner
    ) {
      ordinaryAuthorizationPointerStorage().removeItem(storageKey)
      if (ordinaryAuthorizationPointerStorage().getItem(storageKey) !== null) {
        throw new Error(
          'ordinary browser authorization: pointer removal failed',
        )
      }
    }
    await deleteOrdinaryAuthorizationRecordRevision(cleaning)
  }

  async rejectAndCleanup(record: OrdinaryAuthorizationRecord): Promise<void> {
    if (record.cleanupStarted) {
      await this.finishCleanup(record)
      return
    }
    if (record.parPhase !== 'admitted') {
      throw new Error(
        'ordinary browser authorization: rejection phase is invalid',
      )
    }
    const rejecting = await requireOrdinaryAuthorizationRejection(record)
    await settleOrdinaryAuthorization(rejecting, 'reject')
    await this.startAndFinishCleanup(rejecting)
  }

  private async rejectSubmittedAndCleanup(
    record: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    await cancelSubmittedOrdinaryAuthorization(record)
    await this.startAndFinishCleanup(record)
  }

  async terminalOnlyAndCleanup(
    record: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    this.assertExactPointer(record)
    await this.terminalOnlyAndCleanupWithoutPointer(record)
  }

  async terminalOnlyAndCleanupWithoutPointer(
    record: OrdinaryAuthorizationRecord,
  ): Promise<void> {
    if (
      record.parPhase !== 'admitted' ||
      record.rejectionRequired ||
      record.cleanupStarted
    ) {
      throw new Error(
        'ordinary browser authorization: terminal phase is invalid',
      )
    }
    await settleOrdinaryAuthorization(record, 'terminal_only')
    await this.startAndFinishCleanup(record)
  }

  async invalidateCurrent(
    generation: CredentialGenerationSnapshot,
  ): Promise<void> {
    assertCredentialGenerationSnapshot(this.binding, generation)
    const pointer = parseOrdinaryAuthorizationPointer(
      ordinaryAuthorizationPointerStorage().getItem(this.storageKey),
    )
    const record = await loadOrdinaryAuthorizationRecord(
      ordinaryAuthorizationSlotKey(this.binding, generation.tabOwner),
    )
    if (!record) {
      if (pointer) {
        throw new Error(
          'ordinary browser authorization: pointer has no custody',
        )
      }
      return
    }
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      record.intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    if (record.cleanupStarted) {
      await this.finishCleanup(record)
    } else if (record.parPhase === 'admitted') {
      await this.rejectAndCleanup(record)
    } else if (record.parPhase === 'submitted') {
      await this.rejectSubmittedAndCleanup(record)
    } else {
      await this.cleanupPreparedRecordWithoutPointer(record)
    }
  }

  async invalidateSignedOutLifecycle(): Promise<void> {
    const batch = await loadOrdinaryAuthorizationInventory()
    const records = await Promise.all(
      batch.snapshots.map((snapshot) =>
        classifyOrdinaryAuthorizationRecordEnvelope(snapshot),
      ),
    )
    const matching = records.filter(
      (record) =>
        record.issuer === this.binding.issuer &&
        record.clientId === this.binding.clientId &&
        new URL(record.redirectUri).origin ===
          new URL(this.binding.redirectUri).origin,
    )
    for (const record of matching) {
      if (record.cleanupStarted) {
        await this.finishCleanup(record)
      } else if (record.parPhase === 'admitted') {
        await this.rejectAndCleanup(record)
      } else if (record.parPhase === 'submitted') {
        await this.rejectSubmittedAndCleanup(record)
      } else {
        await this.cleanupPreparedRecordWithoutPointer(record)
      }
    }
    batch.commit()
    if (batch.hasMore) throw new OrdinaryAuthorizationPendingError()
  }
}
