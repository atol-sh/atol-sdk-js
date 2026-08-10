const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/
const MAX_RETURN_TO_LENGTH = 2048

/**
 * Normalize application navigation state without turning it into an OAuth
 * redirect URI. Only an absolute-path reference on the registered
 * redirect URI's origin is accepted.
 */
export function normalizeSameOriginReturnTo(
  value: string | undefined,
  redirectUri: string,
): string | undefined {
  if (value === undefined) return undefined
  if (
    value.length === 0 ||
    value.length > MAX_RETURN_TO_LENGTH ||
    CONTROL_CHARACTER.test(value) ||
    !value.startsWith('/') ||
    value.startsWith('//')
  ) {
    throw new Error('returnTo must be a same-origin absolute path')
  }

  let redirect: URL
  let target: URL
  try {
    redirect = new URL(redirectUri)
    target = new URL(value, redirect.origin)
  } catch {
    throw new Error('returnTo must be a same-origin absolute path')
  }
  if (
    target.origin !== redirect.origin ||
    target.username !== '' ||
    target.password !== ''
  ) {
    throw new Error('returnTo must be a same-origin absolute path')
  }
  return `${target.pathname}${target.search}${target.hash}`
}
