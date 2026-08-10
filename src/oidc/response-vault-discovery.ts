import { potentiallyTrustworthyURL } from './response-vault-config'
import {
  ACKNOWLEDGE_PATH,
  AUTHORIZATION_INIT_PATH,
  AUTHORIZE_PATH,
  BOOTSTRAP_PATH,
  FINALIZE_PATH,
  ISSUER_BOOTSTRAP_PATH,
  PAR_PATH,
  REJECT_PATH,
  RELAY_PATH,
  RESPONSE_MODE,
  RESPONSE_VAULT_PROTOCOL_VERSION,
  TOKEN_PATH,
  type ResponseVaultConfig,
  type ResponseVaultEndpoints,
} from './response-vault-contract'
import { hasExactMembers } from './strict-json'

const DISCOVERY_METADATA_MEMBERS = [
  'version',
  'response_mode',
  'client_id',
  'redirect_uri',
  'audience',
  'console_origin',
  'bootstrap_endpoint',
  'pushed_authorization_request_endpoint',
  'issuer_bootstrap_endpoint',
  'authorization_init_endpoint',
  'authorization_endpoint',
  'relay_endpoint',
  'acknowledgement_endpoint',
  'finalization_endpoint',
  'rejection_endpoint',
] as const

function exactDiscoveredEndpoint(
  value: unknown,
  expected: string,
  label: string,
): string {
  if (typeof value !== 'string' || value !== expected) {
    throw new Error(`response vault: discovered ${label} is invalid`)
  }
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`response vault: discovered ${label} is invalid`)
  }
  if (
    !potentiallyTrustworthyURL(parsed) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(`response vault: discovered ${label} is invalid`)
  }
  return value
}

export function discoveredEndpoints(
  envelope: Record<string, unknown>,
  config: ResponseVaultConfig,
  clientOrigin: string,
): ResponseVaultEndpoints {
  if (envelope.issuer !== config.issuer) {
    throw new Error('response vault: discovered issuer is invalid')
  }
  const modes = envelope.response_modes_supported
  if (
    !Array.isArray(modes) ||
    modes.length === 0 ||
    modes.length > 64 ||
    modes.some(
      (mode) =>
        typeof mode !== 'string' ||
        mode.length === 0 ||
        mode.length > 128,
    ) ||
    modes.filter((mode) => mode === RESPONSE_MODE).length !== 1
  ) {
    throw new Error('response vault: discovered response modes are invalid')
  }
  const metadata = envelope.atol_console_browser_authorization
  if (
    metadata === null ||
    typeof metadata !== 'object' ||
    Array.isArray(metadata) ||
    !hasExactMembers(
      metadata as Record<string, unknown>,
      DISCOVERY_METADATA_MEMBERS,
    )
  ) {
    throw new Error('response vault: browser authorization metadata is invalid')
  }
  const browser = metadata as Record<string, unknown>
  if (
    browser.version !== RESPONSE_VAULT_PROTOCOL_VERSION ||
    browser.response_mode !== RESPONSE_MODE ||
    browser.client_id !== config.clientId ||
    browser.redirect_uri !== config.redirectUri ||
    browser.audience !== config.audience ||
    browser.console_origin !== clientOrigin
  ) {
    throw new Error('response vault: browser authorization binding is invalid')
  }

  const authorization = exactDiscoveredEndpoint(
    browser.authorization_endpoint,
    `${config.issuer}${AUTHORIZE_PATH}`,
    'authorization endpoint',
  )
  exactDiscoveredEndpoint(
    envelope.authorization_endpoint,
    authorization,
    'standard authorization endpoint',
  )

  return {
    bootstrap: exactDiscoveredEndpoint(
      browser.bootstrap_endpoint,
      `${clientOrigin}${BOOTSTRAP_PATH}`,
      'bootstrap endpoint',
    ),
    pushedAuthorizationRequest: exactDiscoveredEndpoint(
      browser.pushed_authorization_request_endpoint,
      `${clientOrigin}${PAR_PATH}`,
      'pushed authorization request endpoint',
    ),
    issuerBootstrap: exactDiscoveredEndpoint(
      browser.issuer_bootstrap_endpoint,
      `${config.issuer}${ISSUER_BOOTSTRAP_PATH}`,
      'issuer bootstrap endpoint',
    ),
    authorizationInit: exactDiscoveredEndpoint(
      browser.authorization_init_endpoint,
      `${config.issuer}${AUTHORIZATION_INIT_PATH}`,
      'authorization init endpoint',
    ),
    authorization,
    relay: exactDiscoveredEndpoint(
      browser.relay_endpoint,
      `${clientOrigin}${RELAY_PATH}`,
      'relay endpoint',
    ),
    acknowledgement: exactDiscoveredEndpoint(
      browser.acknowledgement_endpoint,
      `${clientOrigin}${ACKNOWLEDGE_PATH}`,
      'acknowledgement endpoint',
    ),
    finalization: exactDiscoveredEndpoint(
      browser.finalization_endpoint,
      `${clientOrigin}${FINALIZE_PATH}`,
      'finalization endpoint',
    ),
    rejection: exactDiscoveredEndpoint(
      browser.rejection_endpoint,
      `${clientOrigin}${REJECT_PATH}`,
      'rejection endpoint',
    ),
    token: exactDiscoveredEndpoint(
      envelope.token_endpoint,
      `${config.issuer}${TOKEN_PATH}`,
      'token endpoint',
    ),
  }
}
