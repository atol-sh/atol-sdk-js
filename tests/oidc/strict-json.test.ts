import { describe, expect, it } from 'vitest'
import {
  hasExactMembers,
  parseUniqueFlatJSONObject,
  parseUniqueJSONObject,
} from '../../src/oidc/strict-json'

describe('parseUniqueFlatJSONObject', () => {
  it('parses every supported primitive with insignificant whitespace', () => {
    expect(
      parseUniqueFlatJSONObject(
        ' \n { "escaped\\nkey" : "value\\ttext", "yes": true, "no": false, "nil": null, "number": -1.25e2 } \t',
      ),
    ).toEqual({
      'escaped\nkey': 'value\ttext',
      yes: true,
      no: false,
      nil: null,
      number: -125,
    })
    expect(parseUniqueFlatJSONObject(' { } ')).toEqual({})
  })

  it.each([
    ['empty input', ''],
    ['oversized input', `{"value":"${'x'.repeat(128)}"}`],
    ['non-object root', '[]'],
    ['non-string member', '{value:1}'],
    ['invalid string escape', '{"\\x":1}'],
    ['unterminated string', '{"value":"unterminated}'],
    ['missing colon', '{"value" 1}'],
    ['nested object', '{"value":{}}'],
    ['nested array', '{"value":[]}'],
    ['unsupported primitive', '{"value":undefined}'],
    ['non-finite number', '{"value":1e999}'],
    ['missing comma', '{"a":1 "b":2}'],
    ['trailing object data', '{"a":1} true'],
    ['trailing empty-object data', '{} true'],
    ['duplicate member', '{"a":1,"a":2}'],
  ])('rejects %s', (_name, input) => {
    const maximum = _name === 'oversized input' ? 32 : undefined
    expect(() => parseUniqueFlatJSONObject(input, maximum)).toThrow()
  })
})

describe('parseUniqueJSONObject', () => {
  it('parses standard nested objects and arrays', () => {
    expect(
      parseUniqueJSONObject(
        '{"issuer":"https://id.example.com","modes":["code","vault"],"metadata":{"version":1,"enabled":true},"empty":[]}',
      ),
    ).toEqual({
      issuer: 'https://id.example.com',
      modes: ['code', 'vault'],
      metadata: { version: 1, enabled: true },
      empty: [],
    })
  })

  it.each([
    ['nested object duplicate', '{"metadata":{"version":1,"version":1}}'],
    ['object in array duplicate', '{"items":[{"name":"a","name":"b"}]}'],
    ['root duplicate', '{"issuer":"a","issuer":"b"}'],
    ['trailing data', '{"issuer":"a"}[]'],
    ['trailing array comma', '{"items":[1,]}'],
    ['missing array comma', '{"items":[1 2]}'],
    ['trailing object comma', '{"metadata":{"version":1,}}'],
    ['excessive nesting', `{"value":${'['.repeat(66)}0${']'.repeat(66)}}`],
  ])('rejects %s', (_name, input) => {
    expect(() => parseUniqueJSONObject(input)).toThrow()
  })
})

describe('hasExactMembers', () => {
  it('accepts required and permitted optional members only', () => {
    expect(hasExactMembers({ a: 1 }, ['a'], ['b'])).toBe(true)
    expect(hasExactMembers({ a: 1, b: 2 }, ['a'], ['b'])).toBe(true)
  })

  it('rejects missing required and unexpected members', () => {
    expect(hasExactMembers({ b: 2 }, ['a'], ['b'])).toBe(false)
    expect(hasExactMembers({ a: 1, c: 3 }, ['a'], ['b'])).toBe(false)
  })
})
