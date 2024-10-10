import { randomInt } from 'crypto'

export const DIGITS = '1234567890'
export const LOWERS = 'abcdefghijklmnopqrstuvwxyz'
export const UPPERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
export const SYMBOLS = '~`! @#$%^&*()-_+={}[]|\\;:\'"<>,./?'

/**
 * Generates a random password string from the specified vocabulary and length.
 *
 * @param {number} length - The length of the password to generate.
 * @param {string} [vocabulary=DIGITS + LOWERS + UPPERS + SYMBOLS] - A string containing the set of characters to use in the password.
 * @returns {string} A randomly generated password string.
 * @throws {TypeError} If the vocabulary is not a non-empty string.
 * @throws {TypeError} If the length is not a positive integer.
 */
export function createPassword (length, vocabulary = DIGITS + LOWERS + UPPERS + SYMBOLS) {
  if (!Number.isInteger(length) || length <= 0) { throw new TypeError('Length must be a positive integer') }
  if (typeof vocabulary !== 'string' || vocabulary.length === 0) { throw new TypeError('Vocabulary must be a non-empty string') }

  const a = Array.from(vocabulary)
  return Array.from({ length }, () => a[randomInt(0, a.length)]).join('')
}

export default createPassword
