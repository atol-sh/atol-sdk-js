export class AtolBrowserAuthCleanupError extends Error {
  readonly code = 'browser_auth_cleanup_failed'

  constructor() {
    super('browser auth client cleanup failed')
    this.name = 'AtolBrowserAuthCleanupError'
  }
}
