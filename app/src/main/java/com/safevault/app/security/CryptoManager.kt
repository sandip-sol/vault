package com.safevault.app.security

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AEAD primitives for the vault. AES-256-GCM only; no custom constructions.
 *
 * Payload format (schema v2):
 *
 *     "v2." + Base64( IV(12) || ciphertext || GCM tag(16) )
 *
 * Every payload is bound to a context string via GCM associated data, so a
 * ciphertext lifted out of the `password` column cannot be replayed into
 * `username` — the auth tag will not verify.
 *
 * Schema v1 (legacy) was bare Base64(IV || ciphertext) with no AAD and a key
 * derived straight from the master password. [openLegacy] still reads it so an
 * existing vault can be opened exactly once and re-encrypted under the envelope
 * hierarchy. See [LegacyVaultMigration].
 */
object CryptoManager {

    const val SCHEMA_LEGACY = 1
    const val SCHEMA_CURRENT = 2

    private const val PREFIX_V2 = "v2."
    private const val KEY_BITS = 256
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val TRANSFORM = "AES/GCM/NoPadding"

    private val random = SecureRandom()

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    /** A fresh random data-encryption key. Never derived from a password. */
    fun newDataKey(): SecretKey =
        KeyGenerator.getInstance("AES").apply { init(KEY_BITS, random) }.generateKey()

    fun keyFromBytes(bytes: ByteArray): SecretKey = SecretKeySpec(bytes, "AES")

    // ── Sealing ────────────────────────────────────────────────────────────

    fun seal(plain: ByteArray, key: SecretKey, aad: String): String {
        val iv = randomBytes(IV_BYTES)
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            updateAAD(aad.toByteArray(Charsets.UTF_8))
        }
        return PREFIX_V2 + Base64.encodeToString(iv + cipher.doFinal(plain), Base64.NO_WRAP)
    }

    fun open(payload: String, key: SecretKey, aad: String): ByteArray {
        require(payload.startsWith(PREFIX_V2)) { "Not a v2 payload" }
        val data = Base64.decode(payload.removePrefix(PREFIX_V2), Base64.NO_WRAP)
        require(data.size > IV_BYTES) { "Truncated payload" }
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, data.copyOf(IV_BYTES)))
            updateAAD(aad.toByteArray(Charsets.UTF_8))
        }
        return cipher.doFinal(data, IV_BYTES, data.size - IV_BYTES)
    }

    fun encrypt(plain: String, key: SecretKey, aad: String): String =
        seal(plain.toByteArray(Charsets.UTF_8), key, aad)

    fun decrypt(payload: String, key: SecretKey, aad: String): String =
        String(open(payload, key, aad), Charsets.UTF_8)

    /** True if [payload] was written by this schema version. */
    fun isCurrentSchema(payload: String): Boolean = payload.startsWith(PREFIX_V2)

    // ── Key wrapping (envelope) ────────────────────────────────────────────

    fun wrapKey(dek: SecretKey, kek: SecretKey, aad: String): String =
        seal(dek.encoded, kek, aad)

    /** @throws javax.crypto.AEADBadTagException if [kek] is wrong or the blob was tampered with. */
    fun unwrapKey(payload: String, kek: SecretKey, aad: String): SecretKey =
        keyFromBytes(open(payload, kek, aad))

    // ── Legacy (schema v1) ─────────────────────────────────────────────────

    /** Reads a pre-envelope payload: bare Base64(IV || ciphertext), no AAD. */
    fun openLegacy(payload: String, key: SecretKey): String {
        val data = Base64.decode(payload, Base64.NO_WRAP)
        require(data.size > IV_BYTES) { "Truncated legacy payload" }
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, data.copyOf(IV_BYTES)))
        }
        return String(cipher.doFinal(data, IV_BYTES, data.size - IV_BYTES), Charsets.UTF_8)
    }
}
