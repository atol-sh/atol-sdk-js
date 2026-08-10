export function rfc3339NanoNanoseconds(value: string): bigint {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(
      value,
    )
  if (!match) {
    throw new Error('browser authorization: deadline is invalid')
  }
  const [year, month, day, hour, minute, second] = match
    .slice(1, 7)
    .map(Number)
  if (year < 1970 || second > 59) {
    throw new Error('browser authorization: deadline is invalid')
  }
  const fraction = (match[7] ?? '').padEnd(9, '0')
  const parsed = Date.UTC(
    year,
    month - 1,
    day,
    hour,
    minute,
    second,
    0,
  )
  const date = new Date(parsed)
  if (
    !Number.isSafeInteger(parsed) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second ||
    date.getUTCMilliseconds() !== 0
  ) {
    throw new Error('browser authorization: deadline is invalid')
  }
  return BigInt(parsed) * 1_000_000n + BigInt(fraction || '0')
}

export function rfc3339NanoMilliseconds(value: string): number {
  const nanoseconds = rfc3339NanoNanoseconds(value)
  const milliseconds = Number(nanoseconds / 1_000_000n)
  if (!Number.isSafeInteger(milliseconds)) {
    throw new Error('browser authorization: deadline is invalid')
  }
  return milliseconds
}
