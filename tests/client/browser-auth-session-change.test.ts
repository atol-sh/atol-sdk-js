/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it } from 'vitest'
import {
  makeAccessToken,
  makeClient,
  makeIDToken,
  manager,
} from './browser-auth-harness'

describe('createAtolBrowserAuth -- onSessionChange', () => {
  it('fires immediately with the current session and again on login', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    const client = makeClient()
    const seen: boolean[] = []
    const unsub = client.onSessionChange((s) => seen.push(s.isAuthenticated))
    // Immediate fire: unauthenticated.
    expect(seen[0]).toBe(false)

    await client.init()
    // Eventually reflects authenticated.
    expect(seen[seen.length - 1]).toBe(true)
    unsub()
    client.destroy()
  })

  it('fires on logout with an unauthenticated session', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt',
    })
    const client = makeClient()
    await client.init()
    let latest = true
    client.onSessionChange((s) => (latest = s.isAuthenticated))
    await client.logout()
    expect(latest).toBe(false)
    client.destroy()
  })
})
