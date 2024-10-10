import { describe, it } from 'node:test'
import assert from 'node:assert'

import createPassword from './createPassword.mjs'

describe('# createPassword', () => {
  const DIGITS = '1234567890'
  const LOWERS = 'abcdefghijklmnopqrstuvwxyz'
  const UPPERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const SYMBOLS = '~`! @#$%^&*()-_+={}[]|\\:\'"<>,./?'
  const GREEK = 'ΑαΒβΓγΔδΕεΖζΗηΘθΙιΚκΛλΜμΝνΞξΟοΠπΡρΣσςΤτΥυΦφΧχΨψΩω'
  const EMOJIS = '😀😁😂🤣😃😄😅😆😉😊😋😎😍😘'

  it('should generate a password of the specified length', () => {
    const password = createPassword(DIGITS + LOWERS + UPPERS, 16)
    assert.strictEqual(password.length, 16)
  })

  it('should use only characters from the vocabulary', () => {
    const vocabulary = 'abc123'
    const password = createPassword(vocabulary, 100)
    for (const char of password) {
      assert.ok(vocabulary.includes(char))
    }
  })

  it('should throw a TypeError if vocabulary is empty', () => {
    assert.throws(() => {
      createPassword('', 10)
    }, TypeError)
  })

  it('should throw a TypeError if length is not a positive integer', () => {
    assert.throws(() => {
      createPassword(DIGITS, 0)
    }, TypeError)

    assert.throws(() => {
      createPassword(DIGITS, -5)
    }, TypeError)

    assert.throws(() => {
      createPassword(DIGITS, 3.5)
    }, TypeError)

    assert.throws(() => {
      createPassword(DIGITS, '10')
    }, TypeError)
  })

  it('should handle large vocabularies with Unicode characters', () => {
    const password = createPassword(GREEK, 20)
    assert.strictEqual(password.length, 20)
    for (const char of password) {
      assert.ok(GREEK.includes(char))
    }
  })

  it('should handle vocabulary with surrogate pairs (e.g., emojis)', () => {
    const password = createPassword(EMOJIS, 10)
    assert.strictEqual(Array.from(password).length, 10)
    for (const char of password) {
      assert.ok(EMOJIS.includes(char))
    }
  })

  it('should generate different passwords on subsequent calls', () => {
    const vocabulary = DIGITS + LOWERS + UPPERS + SYMBOLS
    const password1 = createPassword(vocabulary, 32)
    const password2 = createPassword(vocabulary, 32)
    assert.notStrictEqual(password1, password2)
  })

  it('should include symbols when provided in the vocabulary', () => {
    const password = createPassword(SYMBOLS, 50)
    for (const char of password) {
      assert.ok(SYMBOLS.includes(char))
    }
  })

  it('should correctly handle vocabulary with repeated characters', () => {
    const vocabulary = 'aaabbbccc'
    const password = createPassword(vocabulary, 20)
    for (const char of password) {
      assert.ok(['a', 'b', 'c'].includes(char))
    }
  })
})
