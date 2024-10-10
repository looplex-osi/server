import { randomInt } from 'crypto'

export const DIGITS = '1234567890'
export const LOWERS = 'abcdefghijklmnopqrstuvwxyz'
export const UPPERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
export const SYMBOLS = '~`! @#$%^&*()-_+={}[]|\\;:\'"<>,./?'

export function createPassword (vocabulary = DIGITS + LOWERS + UPPERS + SYMBOLS, length) {
  if (typeof vocabulary !== 'string' || vocabulary.length === 0) { throw new TypeError('Vocabulary must be a non-empty string') }
  if (!Number.isInteger(length) || length <= 0) { throw new TypeError('Length must be a positive integer') }

  const a = Array.from(vocabulary)
  return Array.from({ length }, () => a[randomInt(0, a.length)]).join('')
}

export default createPassword
