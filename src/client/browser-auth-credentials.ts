import { decodeJWTPayload, parseAtolUser } from '../claims/claims'
import { userFromTokenResponse } from '../oidc/oidc'
import {
  rememberTokenEndpointDPoPNonce,
  type TokenResponse,
} from '../oidc/silent-renew'
import {
  ResponseVaultRejectionPendingError,
  ResponseVaultSettlementPendingError,
} from '../oidc/response-vault'
import { verifyAccessToken, verifyIdToken } from '../verify/verify'
import type {
  ApplyTokenOptions,
  BrowserAuthCredentialOperations,
  BrowserAuthRuntime,
  PreparedCredentials,
  PreparedEncryptionState,
  SilentCredentialGrant,
} from './browser-auth-context'
import {
  CANONICAL_ULID,
  StaleCredentialTransactionError,
} from './browser-auth-support'

export function createBrowserAuthCredentialOperations(
  runtime: BrowserAuthRuntime,
): BrowserAuthCredentialOperations {
  function toUser(idToken: string | undefined) {
    if (!idToken) return null
    const user = parseAtolUser(idToken)
    return user.id ? user : null
  }

  function organizationClaim(
    claims: Record<string, unknown>,
    tokenName: string,
    requireCanonical: boolean,
  ): string | undefined {
    const value = claims['atol:org_id']
    if (value === undefined) return undefined
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(
        `${tokenName} has an invalid organization claim`,
      )
    }
    if (requireCanonical && !CANONICAL_ULID.test(value)) {
      throw new Error(
        `${tokenName} organization claim is not a canonical ULID`,
      )
    }
    return value
  }

  async function prepareCredentials(
    tokens: TokenResponse,
    options: ApplyTokenOptions,
  ): Promise<PreparedCredentials> {
    let accessClaims: Record<string, unknown>
    if (options.testSession) {
      try {
        accessClaims = decodeJWTPayload(tokens.access_token)
      } catch {
        throw new Error(
          'token response contains an invalid access token',
        )
      }
    } else {
      accessClaims = (await verifyAccessToken(tokens.access_token, {
        authority: runtime.issuer,
        audience: runtime.audience ?? runtime.issuer,
      })) as Record<string, unknown>
    }

    if (!options.testSession) {
      if (
        typeof tokens.token_type !== 'string' ||
        tokens.token_type.length === 0
      ) {
        throw new Error('token response is missing token_type')
      }
      const tokenType = tokens.token_type.toLowerCase()
      const proofKey =
        options.dpopKey === undefined
          ? runtime.dpop
          : options.dpopKey
      if (proofKey) {
        if (tokenType !== 'dpop') {
          throw new Error(
            'DPoP token exchange returned a non-DPoP access token',
          )
        }
        const cnf = accessClaims.cnf
        const jkt =
          cnf && typeof cnf === 'object'
            ? (cnf as Record<string, unknown>).jkt
            : undefined
        if (
          typeof jkt !== 'string' ||
          jkt !== (await proofKey.thumbprint())
        ) {
          throw new Error(
            'DPoP access token is not bound to this tab key',
          )
        }
      } else if (tokenType === 'dpop') {
        throw new Error(
          'received a DPoP access token without a local DPoP key',
        )
      }
    }

    const idToken =
      tokens.id_token ??
      (options.preserveExistingTokens
        ? runtime.currentIdToken
        : undefined)
    if (!idToken) {
      throw new Error('token response is missing an ID token')
    }

    let idClaims: Record<string, unknown>
    if (options.testSession) {
      try {
        idClaims = decodeJWTPayload(idToken)
      } catch {
        throw new Error('token response contains an invalid ID token')
      }
    } else if (
      !tokens.id_token &&
      options.preserveExistingTokens &&
      runtime.currentIdToken === idToken
    ) {
      idClaims = decodeJWTPayload(idToken)
    } else {
      idClaims = (await verifyIdToken(idToken, {
        authority: runtime.issuer,
        clientId: runtime.clientId,
        nonce: options.expectedNonce,
      })) as Record<string, unknown>
    }

    const accessSubject = accessClaims.sub
    const idSubject = idClaims.sub
    if (
      typeof accessSubject !== 'string' ||
      accessSubject.length === 0 ||
      typeof idSubject !== 'string' ||
      idSubject.length === 0 ||
      accessSubject !== idSubject
    ) {
      throw new Error('access and ID token subjects do not match')
    }
    if (
      runtime.currentUser &&
      runtime.currentUser.id !== idSubject
    ) {
      throw new Error(
        'new credentials changed the authenticated subject',
      )
    }

    const accessOrganizationId = organizationClaim(
      accessClaims,
      'access token',
      !options.testSession,
    )
    const idOrganizationId = organizationClaim(
      idClaims,
      'ID token',
      !options.testSession,
    )
    if (accessOrganizationId !== idOrganizationId) {
      throw new Error(
        'access and ID token organization mismatch',
      )
    }
    if (
      options.enforceExpectedOrganization &&
      accessOrganizationId !== options.expectedOrganizationId
    ) {
      throw new Error(
        'token organization does not match the requested organization',
      )
    }

    const user = toUser(idToken)
    if (!user) throw new Error('ID token has no usable subject')

    return {
      accessToken: tokens.access_token,
      idToken,
      refreshToken: runtime.useRefreshTokens
        ? (tokens.refresh_token ??
          (options.preserveExistingTokens
            ? runtime.refreshToken
            : undefined))
        : undefined,
      tokenType: tokens.token_type,
      organizationId: accessOrganizationId,
      user,
    }
  }

  async function commitPreparedCredentials(
    tokens: TokenResponse,
    prepared: PreparedCredentials,
    options: ApplyTokenOptions = {},
    preparedEncryptionOverride?: PreparedEncryptionState,
  ): Promise<void> {
    if (runtime.destroyed) {
      throw new Error('auth client has been destroyed')
    }
    if (
      options.epoch !== undefined &&
      options.epoch !== runtime.credentialEpoch
    ) {
      throw new StaleCredentialTransactionError()
    }
    runtime.sessionOps.assertApplyCredentialAuthority(options)
    const preparedEncryption =
      preparedEncryptionOverride ??
      (await runtime.sessionOps.prepareEncryptionState(
        prepared.idToken,
      ))
    try {
      if (runtime.destroyed) {
        throw new Error('auth client has been destroyed')
      }
      if (
        options.epoch !== undefined &&
        options.epoch !== runtime.credentialEpoch
      ) {
        throw new StaleCredentialTransactionError()
      }
      runtime.sessionOps.assertApplyCredentialAuthority(options)
    } catch (error) {
      preparedEncryption.key?.fill(0)
      throw error
    }

    const stored: TokenResponse = {
      ...tokens,
      access_token: prepared.accessToken,
      id_token: prepared.idToken,
      refresh_token: prepared.refreshToken,
      token_type: prepared.tokenType,
    }
    try {
      await runtime.enqueueUserStore(() =>
        runtime.manager.storeUser(userFromTokenResponse(stored)),
      )
      if (runtime.destroyed) {
        throw new Error('auth client has been destroyed')
      }
      if (
        options.epoch !== undefined &&
        options.epoch !== runtime.credentialEpoch
      ) {
        throw new StaleCredentialTransactionError()
      }
      runtime.sessionOps.assertApplyCredentialAuthority(options)
    } catch (error) {
      preparedEncryption.key?.fill(0)
      void runtime
        .enqueueUserStore(() => runtime.manager.removeUser())
        .catch(() => undefined)
      throw error
    }

    if (options.advanceEpochOnCommit) runtime.credentialEpoch++
    if (options.replaceDPoPKey) {
      runtime.dpop = options.dpopKey ?? null
    }
    runtime.accessToken = prepared.accessToken
    runtime.currentIdToken = prepared.idToken
    runtime.refreshToken = prepared.refreshToken
    runtime.currentOrganizationId = prepared.organizationId
    runtime.currentUser = prepared.user
    runtime.activeCredentialGeneration =
      options.credentialGeneration

    if (preparedEncryption.replace) {
      runtime.sessionOps.zeroEncKey()
      runtime.encKey = preparedEncryption.key
      runtime.encError = preparedEncryption.error
    }
    try {
      runtime.sessionOps.assertApplyCredentialAuthority(options)
    } catch (error) {
      void runtime.sessionOps.clearSession()
      throw error
    }
    runtime.sessionOps.scheduleRenew()
    runtime.sessionOps.emit()
  }

  async function applyTokensUnlocked(
    tokens: TokenResponse,
    options: ApplyTokenOptions = {},
  ): Promise<void> {
    if (runtime.destroyed) {
      throw new Error('auth client has been destroyed')
    }
    if (
      options.epoch !== undefined &&
      options.epoch !== runtime.credentialEpoch
    ) {
      throw new StaleCredentialTransactionError()
    }
    runtime.sessionOps.assertApplyCredentialAuthority(options)
    const prepared = await prepareCredentials(tokens, options)
    if (runtime.destroyed) {
      throw new Error('auth client has been destroyed')
    }
    if (
      options.epoch !== undefined &&
      options.epoch !== runtime.credentialEpoch
    ) {
      throw new StaleCredentialTransactionError()
    }
    runtime.sessionOps.assertApplyCredentialAuthority(options)
    await commitPreparedCredentials(tokens, prepared, options)
  }

  function applyTokens(
    tokens: TokenResponse,
    options: ApplyTokenOptions = {},
  ): Promise<void> {
    return runtime.enqueueCredentialMutation(() =>
      applyTokensUnlocked(tokens, options),
    )
  }

  async function applyAuthorizationGrantUnlocked(
    grant: SilentCredentialGrant,
    options: ApplyTokenOptions,
  ): Promise<void> {
    if (
      grant.responseVaultGrant &&
      grant.ordinaryAuthorizationGrant
    ) {
      throw new Error(
        'authorization grant has conflicting settlement custody',
      )
    }
    if (grant.ordinaryAuthorizationGrant) {
      let published = false
      try {
        await applyTokensUnlocked(grant.tokens, options)
        published = true
        await grant.ordinaryAuthorizationGrant.complete()
      } catch (error) {
        if (published) {
          await runtime.sessionOps
            .clearSession()
            .catch(() => undefined)
          throw error
        }
        await grant.ordinaryAuthorizationGrant.compensate()
        throw error
      }
      return
    }
    if (!grant.responseVaultGrant) {
      await applyTokensUnlocked(grant.tokens, options)
      return
    }
    const grantGeneration =
      grant.responseVaultGrant.credentialGeneration
    const responseVaultOptions: ApplyTokenOptions = {
      ...options,
      credentialGeneration: grantGeneration,
    }
    let published = false
    try {
      if (
        options.credentialGeneration !== undefined &&
        (options.credentialGeneration.logout !==
          grantGeneration.logout ||
          options.credentialGeneration.tabOwner !==
            grantGeneration.tabOwner)
      ) {
        throw new StaleCredentialTransactionError()
      }
      if (
        responseVaultOptions.epoch !== undefined &&
        responseVaultOptions.epoch !== runtime.credentialEpoch
      ) {
        throw new StaleCredentialTransactionError()
      }
      runtime.sessionOps.assertApplyCredentialAuthority(
        responseVaultOptions,
      )
      const prepared = await prepareCredentials(
        grant.tokens,
        responseVaultOptions,
      )
      const preparedEncryption =
        await runtime.sessionOps.prepareEncryptionState(
          prepared.idToken,
        )
      if (
        runtime.destroyed ||
        (responseVaultOptions.epoch !== undefined &&
          responseVaultOptions.epoch !== runtime.credentialEpoch)
      ) {
        throw new StaleCredentialTransactionError()
      }
      runtime.sessionOps.assertApplyCredentialAuthority(
        responseVaultOptions,
      )
      if (
        grant.responseVaultGrant.dpopNonce &&
        !grant.dpopKey
      ) {
        throw new Error(
          'response-vault grant is missing its DPoP key',
        )
      }
      await grant.responseVaultGrant.acknowledge()
      await commitPreparedCredentials(
        grant.tokens,
        prepared,
        responseVaultOptions,
        preparedEncryption,
      )
      published = true
      await grant.responseVaultGrant.finalize()
      await grant.responseVaultGrant.completePublication()
      if (grant.responseVaultGrant.dpopNonce) {
        rememberTokenEndpointDPoPNonce(
          grant.dpopKey!,
          `${runtime.issuer}/auth/token`,
          grant.responseVaultGrant.dpopNonce,
        )
      }
    } catch (error) {
      if (
        !published &&
        error instanceof ResponseVaultSettlementPendingError
      ) {
        throw error
      }
      if (published) {
        await runtime.sessionOps
          .clearSession()
          .catch(() => undefined)
      }
      if (
        error instanceof ResponseVaultRejectionPendingError
      ) {
        throw error
      }
      await grant.responseVaultGrant.reject()
      throw error
    }
  }

  function applyAuthorizationGrant(
    grant: SilentCredentialGrant,
    options: ApplyTokenOptions,
  ): Promise<void> {
    return runtime.enqueueCredentialMutation(() =>
      applyAuthorizationGrantUnlocked(grant, options),
    )
  }

  return {
    applyTokens,
    applyAuthorizationGrant,
  }
}
