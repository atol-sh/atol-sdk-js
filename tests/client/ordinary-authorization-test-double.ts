/**
 * Minimal ordinary-authorization custody seam for browser-auth unit tests
 * whose subject is independent of transaction persistence.
 */
export class OrdinaryAuthorizationTestDouble {
  async begin(
    _start?: unknown,
    navigateAuthorization?: (url: string) => void,
  ): Promise<void> {
    navigateAuthorization?.(
      'https://auth.atol.test/auth/authorize' +
        '?client_id=atol_kid_test' +
        '&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A' +
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    )
  }

  async claimCallback() {
    return {
      dpopKey: null,
      compensationRequired: false,
      markCodeIssued: async () => {},
      complete: async () => {},
      discard: async () => {},
      release: async () => {},
    }
  }

  async claimPendingCallback() {
    return null
  }

  async discardCallback(): Promise<void> {}

  async finishPendingCleanup(): Promise<boolean> {
    return false
  }

  async invalidateCurrent(): Promise<void> {}

  async invalidateSignedOutLifecycle(): Promise<void> {}
}
