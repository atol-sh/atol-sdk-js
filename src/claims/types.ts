/**
 * Framework-agnostic shared types for the Atol browser security core.
 *
 * These are the wire-facing shapes the core produces and consumes:
 * the parsed Atol user, permission checks, and the DPoP proof result.
 * They carry no framework dependency, so both @atol-sh/react and any
 * other binding layer re-export them unchanged.
 */

/** Authenticated user parsed from Atol JWT claims. */
export interface AtolUser {
  /** User ID (JWT sub claim). */
  id: string

  /** User's email address. */
  email: string

  /** Whether the user's email address is verified (email_verified claim). */
  emailVerified: boolean

  /** User's display name. */
  name: string

  /** Organization ID (atol:org_id claim). */
  orgId: string

  /** Organization's subscription plan (atol:plan claim). */
  plan: string

  /** User's roles within the organization (atol:roles claim). */
  roles: string[]

  /** How the user authenticated (atol:auth_method claim). */
  authMethod: string

  /** Whether multi-factor auth was completed (atol:mfa_verified claim). */
  mfaVerified: boolean
}

/** A permission check to evaluate. */
export interface PermissionCheck {
  /** Action to check (e.g. "edit", "view", "manage"). */
  action: string

  /** Resource to check against (e.g. "publication", "team:team-123"). */
  resource: string
}

/** Result of a permission check. */
export interface PermissionResult {
  action: string
  resource: string
  allowed: boolean
}

/**
 * Result of `signDPoPProof` / a DPoP-aware token accessor: the current
 * access token plus, when DPoP is active, a matching resource-server
 * proof JWT.
 */
export interface DPoPProofResult {
  /** The current (freshly-renewed) access token. */
  token: string
  /**
   * A DPoP proof JWT (RFC 9449) for the requested (method, url), bound to
   * `token` via its `ath` claim. Undefined when DPoP is not active
   * (`useDPoP` off or WebCrypto unavailable) -- the caller then presents
   * `token` as a plain `Authorization: Bearer` credential.
   */
  proof?: string
}
