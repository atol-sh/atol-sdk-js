/**
 * Parse bounded JSON while rejecting duplicate member names.
 *
 * JSON.parse alone applies "last member wins", which is unsafe for security
 * protocol metadata and envelopes.
 */

const JSON_NUMBER = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/
const MAX_JSON_DEPTH = 64

function skipWhitespace(input: string, start: number): number {
  let index = start
  while (
    index < input.length &&
    (input[index] === ' ' ||
      input[index] === '\n' ||
      input[index] === '\r' ||
      input[index] === '\t')
  ) {
    index++
  }
  return index
}

function readJSONString(
  input: string,
  start: number,
): { value: string; next: number } {
  if (input[start] !== '"') throw new Error('JSON member must be a string')
  let escaped = false
  for (let index = start + 1; index < input.length; index++) {
    const char = input[index]
    if (escaped) {
      escaped = false
      continue
    }
    if (char === '\\') {
      escaped = true
      continue
    }
    if (char !== '"') continue
    const raw = input.slice(start, index + 1)
    let value: unknown
    try {
      value = JSON.parse(raw)
    } catch {
      throw new Error('JSON string is malformed')
    }
    if (typeof value !== 'string') throw new Error('JSON string is malformed')
    return { value, next: index + 1 }
  }
  throw new Error('JSON string is unterminated')
}

function readPrimitive(
  input: string,
  start: number,
): { value: unknown; next: number } {
  if (input[start] === '"') return readJSONString(input, start)
  for (const [literal, value] of [
    ['true', true],
    ['false', false],
    ['null', null],
  ] as const) {
    if (input.startsWith(literal, start)) {
      return { value, next: start + literal.length }
    }
  }
  const match = JSON_NUMBER.exec(input.slice(start))
  if (!match) throw new Error('JSON value is not a supported primitive')
  const value = Number(match[0])
  if (!Number.isFinite(value)) throw new Error('JSON number is not finite')
  return { value, next: start + match[0].length }
}

class UniqueJSONParser {
  private index = 0

  constructor(private readonly input: string) {}

  parseObjectRoot(): Record<string, unknown> {
    this.index = skipWhitespace(this.input, this.index)
    if (this.input[this.index] !== '{') {
      throw new Error('JSON response must be an object')
    }
    const result = this.parseObject(0)
    this.index = skipWhitespace(this.input, this.index)
    if (this.index !== this.input.length) {
      throw new Error('JSON response has trailing data')
    }
    return result
  }

  private parseValue(depth: number): unknown {
    if (depth > MAX_JSON_DEPTH) {
      throw new Error('JSON response nesting is too deep')
    }
    this.index = skipWhitespace(this.input, this.index)
    if (this.input[this.index] === '{') return this.parseObject(depth)
    if (this.input[this.index] === '[') return this.parseArray(depth)
    const primitive = readPrimitive(this.input, this.index)
    this.index = primitive.next
    return primitive.value
  }

  private parseObject(depth: number): Record<string, unknown> {
    this.index++
    this.index = skipWhitespace(this.input, this.index)
    const result: Record<string, unknown> = Object.create(null)
    const seen = new Set<string>()
    if (this.input[this.index] === '}') {
      this.index++
      return result
    }

    for (;;) {
      const key = readJSONString(this.input, this.index)
      if (seen.has(key.value)) {
        throw new Error('JSON response has a duplicate member')
      }
      seen.add(key.value)
      this.index = skipWhitespace(this.input, key.next)
      if (this.input[this.index] !== ':') {
        throw new Error('JSON response is missing a colon')
      }
      this.index++
      result[key.value] = this.parseValue(depth + 1)
      this.index = skipWhitespace(this.input, this.index)
      if (this.input[this.index] === '}') {
        this.index++
        return result
      }
      if (this.input[this.index] !== ',') {
        throw new Error('JSON response is malformed')
      }
      this.index = skipWhitespace(this.input, this.index + 1)
    }
  }

  private parseArray(depth: number): unknown[] {
    this.index++
    this.index = skipWhitespace(this.input, this.index)
    const result: unknown[] = []
    if (this.input[this.index] === ']') {
      this.index++
      return result
    }

    for (;;) {
      result.push(this.parseValue(depth + 1))
      this.index = skipWhitespace(this.input, this.index)
      if (this.input[this.index] === ']') {
        this.index++
        return result
      }
      if (this.input[this.index] !== ',') {
        throw new Error('JSON response is malformed')
      }
      this.index = skipWhitespace(this.input, this.index + 1)
    }
  }
}

export function parseUniqueJSONObject(
  input: string,
  maxBytes = 32 * 1024,
): Record<string, unknown> {
  if (
    input.length === 0 ||
    input.length > maxBytes ||
    new TextEncoder().encode(input).length > maxBytes
  ) {
    throw new Error('JSON response size is invalid')
  }
  return new UniqueJSONParser(input).parseObjectRoot()
}

export function parseUniqueFlatJSONObject(
  input: string,
  maxBytes = 32 * 1024,
): Record<string, unknown> {
  const result = parseUniqueJSONObject(input, maxBytes)
  for (const value of Object.values(result)) {
    if (value !== null && typeof value === 'object') {
      throw new Error('JSON response contains a nested value')
    }
  }
  return result
}

export function hasExactMembers(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const actual = Object.keys(value).sort()
  const permitted = new Set([...required, ...optional])
  return (
    required.every((name) =>
      Object.prototype.hasOwnProperty.call(value, name),
    ) &&
    actual.every((name) => permitted.has(name))
  )
}
