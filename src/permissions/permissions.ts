import type { PermissionCheck } from '../claims/types'
import type { DPoPSigner } from '../oidc/silent-renew'

/** Inputs for a bulk permission load. */
export interface LoadPermissionsOptions {
  /**
   * Control-plane API base URL (e.g. https://api.atol.sh). This is the
   * Connect-RPC host that serves AccessService -- NOT the OIDC issuer
   * (`authority`), which only mints tokens. Mixing them up sends the
   * authorization check to the wrong host.
   */
  apiUrl: string
  /** Publishable key ID (atol_kid_...). */
  keyId: string
  /** Bearer access token for the call. */
  accessToken: string
  /** Authenticated user's ID (JWT sub). */
  userId: string
  /** Authenticated user's org ID. */
  orgId: string
  /** Permission checks to evaluate. */
  checks: PermissionCheck[]
  /**
   * Optional DPoP signer. When the access token is DPoP-bound (`cnf.jkt`),
   * the resource server expects the `DPoP` auth scheme plus a proof whose
   * `ath` claim hashes the access token (RFC 9449 §4.3). Without this a
   * bound token is presented as plain Bearer and a strict server rejects
   * it -- or, worse, the sender-constraint is silently lost on the most
   * security-sensitive call in the SDK.
   */
  dpop?: DPoPSigner
}

/**
 * Bulk-load permissions from the Atol control plane.
 * Uses the batch-check endpoint with the user's JWT + publishable key.
 * Returns a Map keyed by "action:resource" -> boolean.
 */
export async function loadPermissions(
  opts: LoadPermissionsOptions,
): Promise<Map<string, boolean>> {
  const { apiUrl, keyId, accessToken, userId, orgId, checks, dpop } = opts
  const permissions = new Map<string, boolean>()

  if (checks.length === 0) {
    return permissions
  }

  const body = {
    orgId: orgId,
    checks: checks.map((c) => ({
      user: `user:${userId}`,
      relation: c.action,
      object: c.resource,
    })),
  }

  // Use the Connect-go JSON endpoint (not REST) on the control-plane API host.
  const url = `${apiUrl.replace(/\/+$/, '')}/atol.api.v1.AccessService/BatchCheckAccess`
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Atol-Key': keyId,
  }
  // Present the token under the DPoP scheme with a bound proof when the
  // session uses sender-constrained tokens; otherwise plain Bearer.
  if (dpop) {
    headers['Authorization'] = `DPoP ${accessToken}`
    headers['DPoP'] = await dpop.signProof('POST', url, { accessToken })
  } else {
    headers['Authorization'] = `Bearer ${accessToken}`
  }

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    throw new Error(`Permission check failed: HTTP ${response.status}`)
  }

  const data = (await response.json()) as { results?: Array<{ allowed?: boolean }> }
  const results = data.results ?? []

  // Fail loud on a shape mismatch: results are correlated to checks by
  // position, so a short/extra/reordered array would silently misattribute
  // allow/deny across (action, resource) pairs. Deny-by-default only holds
  // when the counts line up.
  if (results.length !== checks.length) {
    throw new Error(
      `Permission check returned ${results.length} results for ${checks.length} checks`,
    )
  }

  for (let i = 0; i < checks.length; i++) {
    const key = `${checks[i].action}:${checks[i].resource}`
    // Strict === true: any non-true value (missing, null, truthy-but-not-
    // boolean) denies.
    permissions.set(key, results[i]?.allowed === true)
  }

  return permissions
}

/** Build the permission map key from action + resource. */
export function permissionKey(action: string, resource: string): string {
  return `${action}:${resource}`
}
