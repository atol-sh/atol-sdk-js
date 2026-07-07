/**
 * Cross-tab token rotation broadcast.
 *
 * When the leader tab rotates tokens, it publishes the new access/id/refresh
 * tokens to a shared `BroadcastChannel`. Follower tabs subscribe to the
 * channel and apply the rotated tokens without running their own renewal,
 * so concurrent open tabs collapse to a single /auth/token POST per cycle.
 *
 * Refresh tokens are deliberately broadcast because the server rotates them
 * on every use (RFC 6749 §10.4). A follower whose refresh token is stale
 * will hit `invalid_grant` on its next renew -- which, under the server's
 * refresh-token reuse detection, invalidates the whole family and signs every
 * tab out. Sharing
 * the rotated value prevents that chain reaction.
 *
 * The channel stays same-origin by construction. If `BroadcastChannel` is
 * unavailable (old Safari, some sandboxed iframes), the helper degrades to
 * a no-op: publish swallows, subscribe never fires. That's a graceful
 * regression to per-tab behavior, not a failure.
 */

export interface TokenRotatedMessage {
  type: "token-rotated"
  /** Access token sent as the Authorization header; always present. */
  accessToken: string
  /** ID token if one was issued on this grant. */
  idToken?: string
  /** Rotated refresh token if the server returned one. */
  refreshToken?: string
  /** ms-since-epoch at which the access token expires; followers compute their own timers off this. */
  expiresAt: number
  /** ms-since-epoch when the message was sent. Lets followers discard stale broadcasts. */
  sentAt: number
}

export interface SessionExpiredMessage {
  type: "session-expired"
  sentAt: number
}

export type BroadcastMessage = TokenRotatedMessage | SessionExpiredMessage

export interface TokenBroadcast {
  publish(message: BroadcastMessage): void
  subscribe(handler: (message: BroadcastMessage) => void): () => void
  close(): void
}

interface BroadcastChannelShape {
  postMessage(message: unknown): void
  addEventListener(
    type: "message",
    handler: (event: { data: unknown }) => void,
  ): void
  removeEventListener(
    type: "message",
    handler: (event: { data: unknown }) => void,
  ): void
  close(): void
}

function getBroadcastChannelCtor(): (new (name: string) => BroadcastChannelShape) | null {
  if (typeof BroadcastChannel === "undefined") return null
  return BroadcastChannel as unknown as new (name: string) => BroadcastChannelShape
}

function isBroadcastMessage(value: unknown): value is BroadcastMessage {
  if (!value || typeof value !== "object") return false
  const t = (value as { type?: unknown }).type
  return t === "token-rotated" || t === "session-expired"
}

/**
 * Create a token broadcast wrapper for the given channel name. Callers must
 * invoke `close()` when the provider unmounts so the underlying channel
 * stops holding a reference.
 */
export function createTokenBroadcast(name: string): TokenBroadcast {
  const Ctor = getBroadcastChannelCtor()
  if (!Ctor) {
    return {
      publish: () => void 0,
      subscribe: () => () => void 0,
      close: () => void 0,
    }
  }
  const channel = new Ctor(name)
  const handlers = new Set<(message: BroadcastMessage) => void>()
  const onMessage = (event: { data: unknown }) => {
    if (!isBroadcastMessage(event.data)) return
    for (const h of handlers) {
      try {
        h(event.data)
      } catch {
        // Handlers must not throw -- swallow to keep the channel healthy.
      }
    }
  }
  channel.addEventListener("message", onMessage)
  return {
    publish(message) {
      channel.postMessage(message)
    },
    subscribe(handler) {
      handlers.add(handler)
      return () => {
        handlers.delete(handler)
      }
    },
    close() {
      channel.removeEventListener("message", onMessage)
      channel.close()
      handlers.clear()
    },
  }
}

/** Whether the current environment supports cross-tab broadcast. Useful for tests. */
export function hasBroadcastSupport(): boolean {
  return getBroadcastChannelCtor() !== null
}
