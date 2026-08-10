/**
 * Vitest setup for @atol-sh/js. Framework-agnostic core -- no
 * @testing-library/jest-dom needed. jsdom provides the DOM/WebCrypto shims
 * individual tests swap in Node's real WebCrypto where they need it.
 */
import { beforeEach } from 'vitest'

function memoryStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => {
      values.delete(key)
    },
    setItem: (key, value) => {
      values.set(key, String(value))
    },
  }
}

if (
  typeof window !== 'undefined' &&
  typeof window.localStorage === 'undefined'
) {
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: memoryStorage(),
  })
}

beforeEach(() => {
  if (typeof window !== 'undefined') {
    window.localStorage?.clear()
  }
})
