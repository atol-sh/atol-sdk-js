/**
 * Public orchestration boundary for ordinary browser PAR authorization.
 */

import type { UserManager } from 'oidc-client-ts'
import { dpopKeyPair } from '../dpop/dpop'
import {
  assertCredentialGenerationSnapshot,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import {
  createAuthorizationRequest,
  ensureAuthorizationRequestState,
  removeAuthorizationRequestState,
  type AuthorizationCodeResponseState,
} from './oidc'
import { OrdinaryAuthorizationCallbackController } from './ordinary-authorization-callback'
import {
  ORDINARY_AUTHORIZATION_POINTER_VERSION,
  ORDINARY_AUTHORIZATION_RECORD_VERSION,
  OrdinaryAuthorizationPendingError,
  canonicalOrdinaryAuthorizationBinding,
  newOrdinaryAuthorizationCancellationSecret,
  ordinaryAuthorizationPointerKey,
  ordinaryAuthorizationRecordExpired,
  ordinaryAuthorizationSlotKey,
  serializedOrdinaryAuthorizationIntent,
  validCanonicalSHA256,
  type OrdinaryAuthorizationBinding,
  type OrdinaryAuthorizationCallbackCustody,
  type OrdinaryAuthorizationCallbackRecovery,
  type OrdinaryAuthorizationDiscoveryContract,
  type OrdinaryAuthorizationPointer,
  type OrdinaryAuthorizationRecord,
  type OrdinaryAuthorizationStart,
} from './ordinary-authorization-model'
import {
  OrdinaryAuthorizationAdmissionTerminalError,
  admitOrdinaryAuthorization,
} from './ordinary-authorization-admission'
import {
  ordinaryAuthorizationDiscoveryContract,
  ordinaryAuthorizationNavigationURL,
} from './ordinary-authorization-protocol'
import {
  addOrdinaryAuthorizationRecord,
  loadOrdinaryAuthorizationRecord,
  ordinaryAuthorizationPointerStorage,
  parseOrdinaryAuthorizationPointer,
  serializeOrdinaryAuthorizationPointer,
  validateOrdinaryAuthorizationInventory,
} from './ordinary-authorization-storage'
import {
  assertOrdinaryAuthorizationRecord,
  assertOrdinaryAuthorizationRecordState,
  canonicalOrdinaryAuthorizationForm,
} from './ordinary-authorization-validation'

export { OrdinaryAuthorizationPendingError }
export type {
  OrdinaryAuthorizationBinding,
  OrdinaryAuthorizationCallbackCustody,
  OrdinaryAuthorizationCallbackRecovery,
  OrdinaryAuthorizationStart,
} from './ordinary-authorization-model'

function navigateBrowser(url: string): void {
  if (typeof window === 'undefined') {
    throw new Error(
      'ordinary browser authorization: browser is unavailable',
    )
  }
  window.location.assign(url)
}

export class OrdinaryBrowserAuthorization {
  private readonly binding: OrdinaryAuthorizationBinding
  private readonly manager: UserManager
  private readonly storageKey: string
  private readonly navigate: (url: string) => void
  private readonly callbacks: OrdinaryAuthorizationCallbackController

  constructor(
    manager: UserManager,
    binding: OrdinaryAuthorizationBinding,
    navigateAuthorization: (url: string) => void = navigateBrowser,
  ) {
    this.binding = canonicalOrdinaryAuthorizationBinding(binding)
    this.manager = manager
    this.storageKey = ordinaryAuthorizationPointerKey(this.binding)
    this.navigate = navigateAuthorization
    this.callbacks = new OrdinaryAuthorizationCallbackController(
      manager,
      this.binding,
      this.storageKey,
    )
  }

  async begin(
    start: OrdinaryAuthorizationStart,
    navigateAuthorization: (url: string) => void = this.navigate,
  ): Promise<void> {
    const generation = start.credentialGeneration
    const intent = serializedOrdinaryAuthorizationIntent(start.intent)
    assertCredentialGenerationSnapshot(this.binding, generation)
    const pending = await this.pendingRecord(generation, intent)
    if (pending) {
      await ensureAuthorizationRequestState(
        this.manager,
        pending.stateId,
        pending.stateStorage,
      )
      if (pending.parPhase === 'admitted') {
        assertCredentialGenerationSnapshot(this.binding, generation)
        navigateAuthorization(
          ordinaryAuthorizationNavigationURL(pending),
        )
        return
      }
      await this.postAndNavigate(
        pending,
        generation,
        navigateAuthorization,
      )
      return
    }

    const dpopKey = start.intent.dpopEnabled
      ? await start.createDPoPKey()
      : null
    if (start.intent.dpopRequired && !dpopKey) {
      throw new Error(
        'DPoP is required but WebCrypto could not create an authorization key',
      )
    }
    const dpopJkt = dpopKey ? await dpopKey.thumbprint() : null
    if (dpopJkt !== null && !validCanonicalSHA256(dpopJkt)) {
      throw new Error(
        'ordinary browser authorization: DPoP thumbprint is invalid',
      )
    }
    assertCredentialGenerationSnapshot(this.binding, generation)
    const created = await createAuthorizationRequest(this.manager, {
      request_type: 'si:r',
      redirect_uri: this.binding.redirectUri,
      response_mode: start.intent.responseMode,
      nonce: start.nonce,
      state: start.state,
      prompt: start.intent.prompt,
      max_age: start.intent.maxAge,
      acr_values: start.intent.acrValues,
      extraQueryParams: start.intent.extraQueryParams,
      dpopJkt: dpopJkt ?? undefined,
    })
    let discovery: OrdinaryAuthorizationDiscoveryContract
    let form: string
    try {
      discovery = ordinaryAuthorizationDiscoveryContract(
        created.metadata as Record<string, unknown>,
        this.binding,
      )
      form = canonicalOrdinaryAuthorizationForm(
        created.authorizationURL,
        this.binding,
        created,
      )
    } catch (error) {
      await removeAuthorizationRequestState(
        this.manager,
        created.stateId,
        created.stateStorage,
      )
      throw error
    }
    const createdAt = Date.now()
    const provisionalExpiresAt =
      createdAt +
      (discovery.ceremonyLifetimeSeconds +
        discovery.authorizationCodeLifetimeSeconds) *
        1000
    if (
      !Number.isSafeInteger(createdAt) ||
      createdAt < 0 ||
      !Number.isSafeInteger(provisionalExpiresAt)
    ) {
      await removeAuthorizationRequestState(
        this.manager,
        created.stateId,
        created.stateStorage,
      )
      throw new Error(
        'ordinary browser authorization: transaction clock is invalid',
      )
    }
    const record: OrdinaryAuthorizationRecord = {
      version: ORDINARY_AUTHORIZATION_RECORD_VERSION,
      revision: 1,
      slotKey: ordinaryAuthorizationSlotKey(
        this.binding,
        generation.tabOwner,
      ),
      stateId: created.stateId,
      ...this.binding,
      credentialGeneration: generation,
      intent,
      stateStorage: created.stateStorage,
      stateCreatedAt: created.stateCreatedAt,
      form,
      createdAt,
      provisionalExpiresAt,
      attemptExpiresAtMs: null,
      pushedAuthorizationRequestEndpoint:
        discovery.pushedAuthorizationRequestEndpoint,
      preNavigationCancellationEndpoint:
        discovery.preNavigationCancellationEndpoint,
      settlementEndpoint: discovery.settlementEndpoint,
      authorizationEndpoint: discovery.authorizationEndpoint,
      protocolVersion: discovery.protocolVersion,
      ceremonyLifetimeSeconds: discovery.ceremonyLifetimeSeconds,
      authorizationCodeLifetimeSeconds:
        discovery.authorizationCodeLifetimeSeconds,
      dpopJkt,
      keys: dpopKey ? dpopKeyPair(dpopKey) : null,
      cancellationSecret:
        newOrdinaryAuthorizationCancellationSecret(),
      parPhase: 'prepared',
      requestUri: null,
      terminalProof: null,
      rootExpiresAt: null,
      rootExpiresAtMs: null,
      custodyExpiresAtMs: null,
      callbackClaimId: null,
      callbackClaimExpiresAtMs: null,
      callbackCode: null,
      callbackCodeHash: null,
      compensationRequired: false,
      rejectionRequired: false,
      cleanupStarted: false,
    }
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    try {
      await addOrdinaryAuthorizationRecord(record)
    } catch (error) {
      await removeAuthorizationRequestState(
        this.manager,
        created.stateId,
        created.stateStorage,
      )
      const winner = await this.pendingRecord(generation, intent)
      if (!winner) throw error
      await ensureAuthorizationRequestState(
        this.manager,
        winner.stateId,
        winner.stateStorage,
      )
      if (winner.parPhase === 'admitted') {
        navigateAuthorization(
          ordinaryAuthorizationNavigationURL(winner),
        )
      } else {
        await this.postAndNavigate(
          winner,
          generation,
          navigateAuthorization,
        )
      }
      return
    }
    const pointer: OrdinaryAuthorizationPointer = {
      version: ORDINARY_AUTHORIZATION_POINTER_VERSION,
      stateId: record.stateId,
      tabOwnerGeneration: generation.tabOwner,
    }
    const serializedPointer =
      serializeOrdinaryAuthorizationPointer(pointer)
    try {
      ordinaryAuthorizationPointerStorage().setItem(
        this.storageKey,
        serializedPointer,
      )
      if (
        ordinaryAuthorizationPointerStorage().getItem(
          this.storageKey,
        ) !== serializedPointer
      ) {
        throw new Error(
          'ordinary browser authorization: pointer was superseded',
        )
      }
    } catch (error) {
      await this.callbacks.cleanupRecordWithoutPointer(record)
      throw error
    }
    await this.postAndNavigate(
      record,
      generation,
      navigateAuthorization,
    )
  }

  claimCallback(
    callback: AuthorizationCodeResponseState,
    generation: CredentialGenerationSnapshot,
  ): Promise<OrdinaryAuthorizationCallbackCustody> {
    return this.callbacks.claimCallback(callback, generation)
  }

  claimPendingCallback(
    generation: CredentialGenerationSnapshot,
  ): Promise<OrdinaryAuthorizationCallbackRecovery | null> {
    return this.callbacks.claimPendingCallback(generation)
  }

  discardCallback(
    callback: AuthorizationCodeResponseState,
    generation: CredentialGenerationSnapshot,
  ): Promise<void> {
    return this.callbacks.discardCallback(callback, generation)
  }

  finishPendingCleanup(
    generation: CredentialGenerationSnapshot,
  ): Promise<boolean> {
    return this.callbacks.finishPendingCleanup(generation)
  }

  invalidateCurrent(
    generation: CredentialGenerationSnapshot,
  ): Promise<void> {
    return this.callbacks.invalidateCurrent(generation)
  }

  invalidateSignedOutLifecycle(): Promise<void> {
    return this.callbacks.invalidateSignedOutLifecycle()
  }

  private async pendingRecord(
    generation: CredentialGenerationSnapshot,
    intent: string,
  ): Promise<OrdinaryAuthorizationRecord | null> {
    const record = await loadOrdinaryAuthorizationRecord(
      ordinaryAuthorizationSlotKey(
        this.binding,
        generation.tabOwner,
      ),
    )
    const pointer = parseOrdinaryAuthorizationPointer(
      ordinaryAuthorizationPointerStorage().getItem(this.storageKey),
    )
    if (!record) {
      await validateOrdinaryAuthorizationInventory()
      if (pointer) {
        throw new Error(
          'ordinary browser authorization: pointer has no custody',
        )
      }
      return null
    }
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    if (record.cleanupStarted) {
      await this.callbacks.finishCleanup(record)
      return null
    }
    if (record.rejectionRequired) {
      await this.callbacks.invalidateCurrent(generation)
      return null
    }
    const expected: OrdinaryAuthorizationPointer = {
      version: ORDINARY_AUTHORIZATION_POINTER_VERSION,
      stateId: record.stateId,
      tabOwnerGeneration: generation.tabOwner,
    }
    const serialized =
      serializeOrdinaryAuthorizationPointer(expected)
    if (pointer === null) {
      ordinaryAuthorizationPointerStorage().setItem(
        this.storageKey,
        serialized,
      )
      if (
        ordinaryAuthorizationPointerStorage().getItem(
          this.storageKey,
        ) !== serialized
      ) {
        throw new Error(
          'ordinary browser authorization: pointer restoration failed',
        )
      }
    } else if (
      pointer.stateId !== expected.stateId ||
      pointer.tabOwnerGeneration !== expected.tabOwnerGeneration
    ) {
      throw new Error(
        'ordinary browser authorization: pointer custody mismatch',
      )
    }
    if (
      ordinaryAuthorizationRecordExpired(record) &&
      record.parPhase !== 'submitted'
    ) {
      throw new OrdinaryAuthorizationPendingError()
    }
    await validateOrdinaryAuthorizationInventory()
    return record
  }

  private async postAndNavigate(
    record: OrdinaryAuthorizationRecord,
    generation: CredentialGenerationSnapshot,
    navigateAuthorization: (url: string) => void,
  ): Promise<void> {
    assertOrdinaryAuthorizationRecord(
      record,
      this.binding,
      generation,
      record.intent,
    )
    await assertOrdinaryAuthorizationRecordState(record)
    if (
      ordinaryAuthorizationRecordExpired(record) &&
      record.parPhase !== 'submitted'
    ) {
      throw new OrdinaryAuthorizationPendingError()
    }
    assertCredentialGenerationSnapshot(this.binding, generation)
    let bound: OrdinaryAuthorizationRecord
    try {
      bound = await admitOrdinaryAuthorization(record)
    } catch (error) {
      if (
        error instanceof
        OrdinaryAuthorizationAdmissionTerminalError
      ) {
        await this.callbacks.finishCleanup(error.cleaning)
        throw new Error(
          'ordinary browser authorization request was rejected',
        )
      }
      throw error
    }
    assertOrdinaryAuthorizationRecord(
      bound,
      this.binding,
      generation,
      record.intent,
    )
    await assertOrdinaryAuthorizationRecordState(bound)
    assertCredentialGenerationSnapshot(this.binding, generation)
    navigateAuthorization(ordinaryAuthorizationNavigationURL(bound))
  }
}
