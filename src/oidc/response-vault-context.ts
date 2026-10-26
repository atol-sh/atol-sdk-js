import {
  assertCredentialGenerationSnapshot,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import { discoveredEndpoints } from './response-vault-discovery'
import {
  CANONICAL_OPAQUE,
  CSRF_HEADER,
  DEFAULT_OPERATION_TIMEOUT_MS,
  DISCOVERY_PATH,
  MAX_RESPONSE_BODY_BYTES,
  RESPONSE_VAULT_PROTOCOL_VERSION,
  type PendingSettlement,
  type ResponseVaultConfig,
  type ResponseVaultEndpoints,
} from './response-vault-contract'
import { exactCurrentCallback, validateConfig } from './response-vault-config'
import {
  claimResponseVaultExecution,
  type ResponseVaultAuthorization,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultCancellation,
  type ResponseVaultExactGenerationSupersession,
  type ResponseVaultReference,
} from './response-vault-storage'
import { discoveryEnvelope } from './response-vault-wire'
import { NetworkError } from './token-recovery'

const RESPONSE_VAULT_OWNED_IFRAME_ATTRIBUTE =
  'data-atol-response-vault-owned'

/**
 * Shared browser-authorization state and low-level capabilities.
 *
 * Domain layers extend this context in one direction. Keeping transport
 * ownership, lifecycle authority, and in-memory settlement state here avoids
 * hidden globals while preventing internal layers from depending on the
 * public facade.
 */
export abstract class ResponseVaultContext {
  protected readonly config: ResponseVaultConfig
  protected readonly clientOrigin: string
  protected readonly pointerKey: string
  protected lifecycle = 0
  protected readonly ownedRequests = new Set<AbortController>()
  protected readonly ownedWaits = new Set<(reason: Error) => void>()
  protected readonly rejectionFlights = new Map<string, Promise<void>>()
  protected readonly rejectedReferences = new Set<string>()
  protected readonly pendingRejectionCustody =
    new Map<string, ResponseVaultCancellation>()
  protected endpointsAuthority: ResponseVaultEndpoints | undefined
  protected discoveryFlight: Promise<ResponseVaultEndpoints> | undefined
  protected pendingSettlement: PendingSettlement | null = null

  protected constructor(config: ResponseVaultConfig) {
    this.config = validateConfig(config)
    this.clientOrigin = new URL(this.config.redirectUri).origin
    this.pointerKey = 'atol:response-vault:v1:active'
  }

  protected storage(): Storage {
    if (typeof window === 'undefined') {
      throw new Error('response vault: browser storage is unavailable')
    }
    if (window.location.origin !== this.clientOrigin) {
      throw new Error('response vault: current origin is not the client origin')
    }
    return window.sessionStorage
  }

  lifecycleEpoch(): number {
    return this.lifecycle
  }

  protected assertLifecycle(expected: number): void {
    if (this.lifecycleEpoch() !== expected) {
      throw new Error('response vault: authorization lifecycle was superseded')
    }
  }

  protected assertAuthorizationCurrent(
    authorization: ResponseVaultAuthorization,
  ): void {
    this.assertLifecycle(authorization.lifecycleEpoch)
    assertCredentialGenerationSnapshot(
      this.config,
      authorization.credentialGeneration,
    )
  }

  protected assertExpectedGeneration(
    authorization: ResponseVaultAuthorization,
    expected?: CredentialGenerationSnapshot,
  ): void {
    this.assertAuthorizationCurrent(authorization)
    if (
      expected !== undefined &&
      (authorization.credentialGeneration.logout !== expected.logout ||
        authorization.credentialGeneration.tabOwner !== expected.tabOwner)
    ) {
      throw new Error('response vault: authorization authority was superseded')
    }
  }

  protected activeReference(): ResponseVaultReference | null {
    const value = this.storage().getItem(this.pointerKey)
    if (value === null) return null
    if (!CANONICAL_OPAQUE.test(value)) {
      throw new Error(
        'response vault: active authorization reference is corrupt',
      )
    }
    return { version: RESPONSE_VAULT_PROTOCOL_VERSION, id: value }
  }

  protected setActive(reference: ResponseVaultReference): void {
    if (!CANONICAL_OPAQUE.test(reference.id)) {
      throw new Error(
        'response vault: active authorization reference is invalid',
      )
    }
    this.storage().setItem(this.pointerKey, reference.id)
  }

  protected clearActive(reference: ResponseVaultReference): void {
    const storage = this.storage()
    if (storage.getItem(this.pointerKey) === reference.id) {
      storage.removeItem(this.pointerKey)
    }
  }

  protected clearPendingSettlement(
    reference?: ResponseVaultReference,
  ): void {
    if (!reference || this.pendingSettlement?.referenceId === reference.id) {
      this.pendingSettlement = null
    }
  }

  protected executionLeaseDuration(waitMs = 0): number {
    const operationTimeout =
      this.config.operationTimeoutMs ?? DEFAULT_OPERATION_TIMEOUT_MS
    return Math.min(
      5 * 60_000,
      Math.max(30_000, operationTimeout + 1_000, waitMs),
    )
  }

  protected async claimExecution(
    authorization: ResponseVaultAuthorization,
    owner: string,
    allowedStatuses: readonly ResponseVaultAuthorizationStatus[],
    waitMs = 0,
    requireCurrentGeneration = true,
    requireActiveSlot = true,
    supersedeInvalidatedGeneration = false,
    exactSupersession?: ResponseVaultExactGenerationSupersession,
  ): Promise<ResponseVaultAuthorization> {
    return claimResponseVaultExecution(
      authorization,
      owner,
      allowedStatuses,
      this.executionLeaseDuration(waitMs),
      requireCurrentGeneration,
      requireActiveSlot,
      supersedeInvalidatedGeneration,
      exactSupersession,
    )
  }

  isCleanCallback(): boolean {
    return exactCurrentCallback(this.config.redirectUri)
  }

  protected markOwnedIframe(iframe: HTMLIFrameElement): void {
    iframe.setAttribute(RESPONSE_VAULT_OWNED_IFRAME_ATTRIBUTE, '')
  }

  isOwnedIframeCallback(): boolean {
    if (!this.isCleanCallback() || typeof window === 'undefined') {
      return false
    }
    try {
      const frame = window.frameElement
      return (
        frame !== null &&
        frame.localName === 'iframe' &&
        frame.hasAttribute(RESPONSE_VAULT_OWNED_IFRAME_ATTRIBUTE)
      )
    } catch {
      return false
    }
  }

  protected async ownedFetch(
    input: string,
    init: RequestInit,
    operation: string,
  ): Promise<Response> {
    const configuredTimeout =
      this.config.operationTimeoutMs ?? DEFAULT_OPERATION_TIMEOUT_MS
    const controller = new AbortController()
    this.ownedRequests.add(controller)
    let timer: ReturnType<typeof setTimeout> | undefined
    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer)
      this.ownedRequests.delete(controller)
    }
    timer = setTimeout(() => {
      controller.abort()
      cleanup()
    }, configuredTimeout)
    let response: Response
    try {
      response = await fetch(input, {
        ...init,
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      })
    } catch (error) {
      cleanup()
      throw new NetworkError(
        `response vault: ${operation} transport failed`,
        error,
      )
    }

    // The deadline remains active through bounded body consumption.
    const readText = response.text.bind(response)
    response.text = async () => {
      try {
        const declaredLength = response.headers.get('Content-Length')
        if (
          declaredLength !== null &&
          (!/^(?:0|[1-9][0-9]*)$/.test(declaredLength) ||
            Number(declaredLength) > MAX_RESPONSE_BODY_BYTES)
        ) {
          throw new Error('response vault: response body exceeds the limit')
        }
        if (!response.body) {
          const body = await readText()
          if (
            new TextEncoder().encode(body).byteLength >
            MAX_RESPONSE_BODY_BYTES
          ) {
            throw new Error('response vault: response body exceeds the limit')
          }
          return body
        }
        const reader = response.body.getReader()
        const decoder = new TextDecoder('utf-8', { fatal: true })
        let total = 0
        let body = ''
        try {
          while (true) {
            const chunk = await reader.read()
            if (chunk.done) break
            total += chunk.value.byteLength
            if (total > MAX_RESPONSE_BODY_BYTES) {
              await reader.cancel()
              throw new Error('response vault: response body exceeds the limit')
            }
            body += decoder.decode(chunk.value, { stream: true })
          }
          body += decoder.decode()
          return body
        } finally {
          reader.releaseLock()
        }
      } catch (error) {
        if (
          error instanceof Error &&
          error.message === 'response vault: response body exceeds the limit'
        ) {
          throw error
        }
        throw new NetworkError(
          `response vault: ${operation} response body transport failed`,
          error,
        )
      } finally {
        cleanup()
      }
    }
    return response
  }

  protected async endpointRegistry(): Promise<ResponseVaultEndpoints> {
    if (this.endpointsAuthority) return this.endpointsAuthority
    if (this.discoveryFlight) return this.discoveryFlight

    const lifecycleEpoch = this.lifecycleEpoch()
    const flight = (async () => {
      const response = await this.ownedFetch(
        `${this.config.issuer}${DISCOVERY_PATH}`,
        {
          method: 'GET',
          credentials: 'omit',
          headers: { Accept: 'application/json' },
        },
        'authorization server discovery',
      )
      const envelope = await discoveryEnvelope(response)
      if (response.status !== 200) {
        throw new Error(
          'response vault: authorization server discovery failed',
        )
      }
      const endpoints = discoveredEndpoints(
        envelope,
        this.config,
        this.clientOrigin,
      )
      this.assertLifecycle(lifecycleEpoch)
      this.endpointsAuthority = endpoints
      return endpoints
    })()
    this.discoveryFlight = flight
    try {
      return await flight
    } finally {
      if (this.discoveryFlight === flight) {
        this.discoveryFlight = undefined
      }
    }
  }

  protected waitForRetry(
    milliseconds: number,
    lifecycleEpoch?: number,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false
      const finish = (error?: Error) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        this.ownedWaits.delete(cancel)
        if (error) reject(error)
        else resolve()
      }
      const cancel = (reason: Error) => finish(reason)
      const timer = setTimeout(() => {
        if (
          lifecycleEpoch !== undefined &&
          this.lifecycleEpoch() !== lifecycleEpoch
        ) {
          finish(
            new Error(
              'response vault: authorization lifecycle was superseded',
            ),
          )
          return
        }
        finish()
      }, milliseconds)
      this.ownedWaits.add(cancel)
    })
  }

  protected async postJSON(
    url: string,
    body: Record<string, unknown>,
    operation: string,
    credentials: RequestCredentials,
    csrf?: string,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (csrf !== undefined) headers[CSRF_HEADER] = csrf
    return this.ownedFetch(
      url,
      {
        method: 'POST',
        credentials,
        headers,
        body: JSON.stringify(body),
      },
      operation,
    )
  }
}
