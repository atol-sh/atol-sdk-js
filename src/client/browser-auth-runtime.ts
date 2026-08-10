import type {
  AtolBrowserAuth,
  AtolBrowserAuthConfig,
} from './browser-auth'
import { createBrowserAuthActions } from './browser-auth-actions'
import { createBrowserAuthCallbackOperations } from './browser-auth-callback'
import { BrowserAuthRuntime } from './browser-auth-context'
import { createBrowserAuthCredentialOperations } from './browser-auth-credentials'
import { createBrowserAuthLifecycleOperations } from './browser-auth-lifecycle'
import { createBrowserAuthRenewalOperations } from './browser-auth-renewal'
import { createBrowserAuthSessionOperations } from './browser-auth-session'

export function createAtolBrowserAuth(
  config: AtolBrowserAuthConfig,
): AtolBrowserAuth {
  const runtime = new BrowserAuthRuntime(config)
  runtime.sessionOps =
    createBrowserAuthSessionOperations(runtime)
  runtime.credentialOps =
    createBrowserAuthCredentialOperations(runtime)
  runtime.renewalOps =
    createBrowserAuthRenewalOperations(runtime)
  runtime.lifecycleOps =
    createBrowserAuthLifecycleOperations(runtime)
  runtime.callbackOps =
    createBrowserAuthCallbackOperations(runtime)
  runtime.sessionOps.installCredentialGenerationStorageListener()
  return createBrowserAuthActions(runtime)
}
