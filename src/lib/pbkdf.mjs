import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt)

const DEFAULT_SALT_LENGTH = 16// NIST 800-132 minimal recommended salt length
const DEFAULT_KEY_LENGTH = 32

/* IMPORTANT:
 *   - <https://nodejs.org/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback>
 *   - [NIST Special Publication 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) -- Recommendation for Password-Based Key Derivation
 */

/**
 * Generates a derived key from a password using the scrypt key derivation function.
 *
 * @param {string | Buffer} password - The password to derive the key from.
 * @param {object} [options={}] - Optional parameters.
 * @param {number} [options.saltlen=DEFAULT_SALT_LENGTH] - Length of the random salt in bytes.
 * @param {number} [options.keylen=DEFAULT_KEY_LENGTH] - Length of the derived key in bytes.
 * @param {number} [options.N=16384] - CPU/memory cost parameter. Must be a power of two greater than one.
 * @param {number} [options.r=8] - Block size parameter.
 * @param {number} [options.p=1] - Parallelization parameter.
 * @param {number} [options.maxmem] - Maximum memory allowed in bytes.
 * @returns {Promise<string>} A promise that resolves to a string containing the salt and derived key in hexadecimal format, separated by a colon.
 * @throws {Error} If the scrypt operation fails.
 */
export async function pbkdf (password, options = {}) {
  const {
    saltlen = DEFAULT_SALT_LENGTH,
    keylen = DEFAULT_KEY_LENGTH,
    ...scryptOptions
  } = options
  const salt = randomBytes(saltlen)
  const derivedKey = await scryptAsync(password, salt, keylen, scryptOptions)
  return `${salt.toString('hex')}:${derivedKey.toString('hex')}`
}

/**
 * Verifies if a given password matches the provided digest using the scrypt key derivation function.
 *
 * @param {string | Buffer} password - The password to verify.
 * @param {string} digest - The digest string containing the salt and derived key in hexadecimal format, separated by a colon.
 * @param {object} [options={}] - Optional parameters.
 * @param {number} [options.keylen=DEFAULT_KEY_LENGTH] - Length of the derived key in bytes.
 * @param {number} [options.N=16384] - CPU/memory cost parameter. Must be a power of two greater than one.
 * @param {number} [options.r=8] - Block size parameter.
 * @param {number} [options.p=1] - Parallelization parameter.
 * @param {number} [options.maxmem] - Maximum memory allowed in bytes.
 * @returns {Promise<boolean>} A promise that resolves to `true` if the password matches the digest, or `false` otherwise.
 * @throws {Error} If the scrypt operation fails or the digest format is invalid.
 */
export async function pbkdfVerify (password, digest, options = {}) {
  const valid = (/^[0-9a-f]+:[0-9a-f]+$/i).test(digest)
  if (!valid) throw new Error('INVALID_DIGEST_FORMAT')
  const [salt, providedDerivedKey] = digest.split(':').map(x => Buffer.from(x, 'hex'))
  const {
    keylen = DEFAULT_KEY_LENGTH,
    ...scryptOptions
  } = options
  const derivedKey = await scryptAsync(password, salt, keylen, scryptOptions)
  return timingSafeEqual(providedDerivedKey, derivedKey)
}
