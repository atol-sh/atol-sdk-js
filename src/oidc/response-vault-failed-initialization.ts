import type { CredentialGenerationSnapshot } from './credential-generation'
import type {
  ResponseVaultAuthorizationMode,
  ResponseVaultCustody,
  ResponseVaultReference,
} from './response-vault-model'

export interface ResponseVaultFailedInitializationAuthority {
  readonly reference: Readonly<ResponseVaultReference>
  readonly mode: ResponseVaultAuthorizationMode
  readonly credentialGeneration: Readonly<CredentialGenerationSnapshot>
}

const failedInitializationAuthorities = new WeakMap<
  object,
  ResponseVaultFailedInitializationAuthority
>()

export class ResponseVaultFailedInitializationModeMismatchError
  extends Error {
  constructor() {
    super('response vault: failed initialization custody mode mismatch')
    this.name = 'ResponseVaultFailedInitializationModeMismatchError'
  }
}

function errorKey(error: unknown): object | undefined {
  if (typeof error === 'function') return error
  return typeof error === 'object' && error !== null
    ? error
    : undefined
}

export function bindResponseVaultFailedInitialization(
  error: unknown,
  custody: ResponseVaultCustody,
): unknown {
  if (!errorKey(error)) return error
  const mode = 'mode' in custody
    ? custody.mode
    : custody.sourceMode ??
      (custody.rejectionProvenance === 'interactive_cancel'
        ? 'interactive'
        : custody.rejectionProvenance === 'failed_init_cancel'
          ? 'iframe'
          : undefined)
  if (mode === undefined) return error
  return bindResponseVaultFailedInitializationAuthority(
    error,
    Object.freeze({
      reference: Object.freeze({ ...custody.reference }),
      mode,
      credentialGeneration: Object.freeze({
        ...custody.credentialGeneration,
      }),
    }),
  )
}

export function bindResponseVaultFailedInitializationAuthority(
  error: unknown,
  authority: ResponseVaultFailedInitializationAuthority,
): unknown {
  const key = errorKey(error)
  if (!key) return error
  if (!failedInitializationAuthorities.has(key)) {
    failedInitializationAuthorities.set(key, authority)
  }
  return error
}

export function takeResponseVaultFailedInitializationAuthority(
  error: unknown,
): ResponseVaultFailedInitializationAuthority | undefined {
  const key = errorKey(error)
  if (!key) return undefined
  const authority = failedInitializationAuthorities.get(key)
  failedInitializationAuthorities.delete(key)
  return authority
}
