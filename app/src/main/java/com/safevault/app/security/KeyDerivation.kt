package com.safevault.app.security

import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Password-based key derivation, versioned so the cost parameters (and one day
 * the algorithm itself) can be raised without stranding existing vaults.
 *
 * Every vault stores the [KdfParams] it was created with. Unlock always derives
 * with the *stored* parameters; new material is written with [CURRENT].
 *
 * Roadmap item: migrate to Argon2id (memory-hard) once a vetted Android
 * implementation is vendored. The version field exists so that becomes a
 * re-wrap of the DEK, not a re-encryption of every record.
 */
object KeyDerivation {

    /** PBKDF2-HMAC-SHA256. */
    const val VERSION_PBKDF2_SHA256 = 1

    const val CURRENT_VERSION = VERSION_PBKDF2_SHA256

    /** Unlock happens on every app start, so this is tuned for phone CPUs. */
    const val VAULT_ITERATIONS = 210_000

    /** Backups are opened rarely and must resist offline attack for years. */
    const val BACKUP_ITERATIONS = 310_000

    private const val SALT_BYTES = 16
    private const val KEY_BITS = 256

    data class KdfParams(
        val version: Int,
        val iterations: Int,
        val salt: ByteArray
    ) {
        override fun equals(other: Any?) = other is KdfParams &&
            version == other.version && iterations == other.iterations &&
            salt.contentEquals(other.salt)

        override fun hashCode() =
            (version * 31 + iterations) * 31 + salt.contentHashCode()
    }

    fun newParams(iterations: Int = VAULT_ITERATIONS) = KdfParams(
        version = CURRENT_VERSION,
        iterations = iterations,
        salt = CryptoManager.randomBytes(SALT_BYTES)
    )

    /**
     * Derives a key-encryption key. The returned key only ever wraps the vault
     * DEK — it never touches record ciphertext directly.
     */
    fun deriveKek(password: CharArray, params: KdfParams): SecretKey {
        require(params.version == VERSION_PBKDF2_SHA256) {
            "Unsupported KDF version ${params.version}"
        }
        val spec = PBEKeySpec(password, params.salt, params.iterations, KEY_BITS)
        try {
            val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).encoded
            return SecretKeySpec(bytes, "AES")
        } finally {
            spec.clearPassword()
        }
    }
}
