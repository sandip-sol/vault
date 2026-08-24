package com.safevault.app.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The biometric key-encryption key. Lives inside the Android Keystore (TEE or
 * StrongBox where the device provides it) and is generated with
 * `setUserAuthenticationRequired(true)` and no validity window, so *every* use
 * must be authorised by a fresh biometric match delivered through a
 * [androidx.biometric.BiometricPrompt.CryptoObject].
 *
 * This is the fix for the previous design, which cached the raw vault key in an
 * EncryptedSharedPreferences file. That key was recoverable by anything that
 * could read app storage — the fingerprint prompt was decoration, not a control.
 * Here the wrapped DEK is useless without a Keystore key that will not operate
 * until the user authenticates.
 *
 * `setInvalidatedByBiometricEnrollment(true)` means enrolling a new fingerprint
 * destroys the key: the vault then falls back to the master password, which is
 * the correct outcome — a newly enrolled finger must not inherit vault access.
 */
class BiometricKeyGuard {

    companion object {
        private const val ALIAS = "safevault_biometric_kek"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM =
            "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/" +
                KeyProperties.ENCRYPTION_PADDING_NONE
        private const val TAG_BITS = 128
    }

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    fun hasKey(): Boolean = keyStore.containsAlias(ALIAS)

    fun deleteKey() {
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
    }

    /**
     * Creates a fresh Keystore key and returns a cipher ready for enrollment.
     * Any previous key is discarded so re-enrolling always starts clean.
     */
    fun createEnrollmentCipher(): Cipher {
        deleteKey()
        generateKey()
        return Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, loadKey()) }
    }

    /**
     * A cipher that will unwrap the DEK once biometric auth succeeds, or null if
     * the Keystore key is gone — deleted, or invalidated by a new enrollment.
     */
    fun createUnlockCipher(iv: ByteArray): Cipher? {
        return try {
            val key = loadKey() ?: return null
            Cipher.getInstance(TRANSFORM)
                .apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv)) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            deleteKey()
            null
        }
    }

    private fun loadKey(): SecretKey? = keyStore.getKey(ALIAS, null) as? SecretKey

    private fun generateKey() {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // 0s validity = authenticate for every single use, Class 3 only.
                    setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                }
            }
            .build()

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }
}
