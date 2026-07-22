/**
 * Cross-tab credential lifecycle signals.
 *
 * Proof-bound tokens are tab-local because every tab owns a different DPoP
 * key. The channel therefore carries signals only. A receiving tab renews
 * with its own key and grant; it never adopts credential material minted for
 * another tab.
 *
 * The channel stays same-origin by construction. If `BroadcastChannel` is
 * unavailable (old Safari, some sandboxed iframes), the helper degrades to
 * a no-op: publish swallows, subscribe never fires. That's a graceful
 * regression to per-tab behavior, not a failure.
 */

export interface CredentialsInvalidatedMessage {
  type: "credentials-invalidated"
  /** ms-since-epoch when the message was sent. */
  sentAt: number
}

export interface SessionEndedMessage {
  type: "session-ended"
  sentAt: number
}

export type BroadcastMessage = CredentialsInvalidatedMessage | SessionEndedMessage

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
  const message = value as { type?: unknown; sentAt?: unknown }
  return (
    (message.type === "credentials-invalidated" || message.type === "session-ended") &&
    typeof message.sentAt === "number" &&
    Number.isFinite(message.sentAt)
  )
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
