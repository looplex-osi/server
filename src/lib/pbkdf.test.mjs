import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'

import { pbkdf, pbkdfVerify } from './pbkdf.mjs'

describe('pbkdf', () => {
  it('should generate a digest in the expected format', async () => {
    const password = 'testpassword'
    const digest = await pbkdf(password)
    assert.match(digest, /^[0-9a-f]+:[0-9a-f]+$/i, 'Digest should be in hex format separated by a colon')
  })
})

describe('pbkdfVerify', () => {
  it('should return true when the password matches', async () => {
    const password = 'testpassword'
    const digest = await pbkdf(password)
    const result = await pbkdfVerify(password, digest)
    assert.strictEqual(result, true, 'Password should match the digest')
  })

  it('should return false when the password does not match', async () => {
    const password = 'testpassword'
    const wrongPassword = 'wrongpassword'
    const digest = await pbkdf(password)
    const result = await pbkdfVerify(wrongPassword, digest)
    assert.strictEqual(result, false, 'Wrong password should not match the digest')
  })

  it('should throw an error when the digest format is invalid', async () => {
    const password = 'testpassword'
    const invalidDigest = 'invaliddigest'
    await assert.rejects(
      async () => {
        await pbkdfVerify(password, invalidDigest)
      },
      (error) => {
        assert.strictEqual(error.message, 'INVALID_DIGEST_FORMAT')
        return true
      }
    )
  })

  it('should work with different options', async () => {
    const password = 'testpassword'
    const options = {
      saltlen: 32,
      keylen: 64,
      N: 32768,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024 // Set maxmem to 64 MB
    }
    const digest = await pbkdf(password, options)
    assert.match(digest, /^[0-9a-f]+:[0-9a-f]+$/i, 'Digest should be in hex format separated by a colon')
    const result = await pbkdfVerify(password, digest, options)
    assert.strictEqual(result, true, 'Password should match the digest with custom options')
  })

  it('should work with password as a Buffer', async () => {
    const password = Buffer.from('testpassword')
    const digest = await pbkdf(password)
    const result = await pbkdfVerify(password, digest)
    assert.strictEqual(result, true, 'Password as Buffer should match the digest')
  })

  it('should work with an empty password', async () => {
    const password = ''
    const digest = await pbkdf(password)
    const result = await pbkdfVerify(password, digest)
    assert.strictEqual(result, true, 'Empty password should match the digest')
  })

  it('should throw an error when digest is empty', async () => {
    const password = 'testpassword'
    const emptyDigest = ''
    await assert.rejects(
      async () => {
        await pbkdfVerify(password, emptyDigest)
      },
      (error) => {
        assert.strictEqual(error.message, 'INVALID_DIGEST_FORMAT')
        return true
      }
    )
  })

  it('should accept digest with uppercase hex letters', async () => {
    const password = 'testpassword'
    const digest = await pbkdf(password)
    const uppercaseDigest = digest.toUpperCase()
    const result = await pbkdfVerify(password, uppercaseDigest)
    assert.strictEqual(result, true, 'Digest with uppercase hex letters should be accepted')
  })

  it('should throw an error when digest contains invalid hex characters', async () => {
    const password = 'testpassword'
    const invalidDigest = 'zzzzzzzzzzzzzzzz:zzzzzzzzzzzzzzzz'
    await assert.rejects(
      async () => {
        await pbkdfVerify(password, invalidDigest)
      },
      (error) => {
        assert.strictEqual(error.message, 'INVALID_DIGEST_FORMAT')
        return true
      }
    )
  })

  it('should throw an error if scrypt operation fails due to invalid parameters', async () => {
    const password = 'testpassword'
    const options = {
      N: 1 // Invalid N parameter
    }
    await assert.rejects(
      async () => {
        await pbkdf(password, options)
      },
      (error) => {
        assert.strictEqual(error.message, 'Invalid scrypt params')
        return true
      }
    )
  })
})
