package com.safevault.app.security

import android.content.Context
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * The vault key hierarchy (roadmap §8, envelope encryption).
 *
 *     Vault DEK          random AES-256, encrypts every record, never stored bare
 *       ├── wrapped by ── password KEK   = PBKDF2(master password, salt)
 *       └── wrapped by ── biometric KEK  = Android Keystore key, auth-required
 *
 * The point of the indirection: records are encrypted under the DEK, and the DEK
 * alone is re-wrapped when the master password changes or a second unlock method
 * is enrolled. Changing the master password therefore rewrites ~100 bytes rather
 * than re-encrypting the whole database, and a backup can carry the same DEK to
 * a new device without touching record ciphertext.
 */
class VaultKeyManager(context: Context) {

    private val appContext = context.applicationContext
    private val prefs = VaultPrefs(appContext)
    private val biometricGuard = BiometricKeyGuard()

    companion object {
        private const val AAD_PASSWORD_DEK = "safevault/dek/password/v2"
        private const val AAD_BIOMETRIC_DEK = "safevault/dek/biometric/v2"
    }

    val isInitialized: Boolean get() = prefs.isInitialized
    val isLegacyVault: Boolean get() = prefs.isLegacyVault
    val isMigrationIncomplete: Boolean get() = prefs.isMigrationIncomplete
    val biometricEnabled: Boolean get() = prefs.biometricEnabled

    // ── Creation ───────────────────────────────────────────────────────────

    /** First run: mint a DEK and seal it under the chosen master password. */
    fun createVault(masterPassword: CharArray): SecretKey {
        val dek = CryptoManager.newDataKey()
        val params = KeyDerivation.newParams()
        val kek = KeyDerivation.deriveKek(masterPassword, params)
        prefs.writeEnvelope(
            params = params,
            wrappedDek = CryptoManager.wrapKey(dek, kek, AAD_PASSWORD_DEK),
            createdAt = System.currentTimeMillis()
        )
        return dek
    }

    /**
     * Installs a DEK recovered from a backup under a new password envelope.
     * Used by restore, which must keep the DEK so restored ciphertext still opens.
     */
    fun adoptDek(dek: SecretKey, masterPassword: CharArray, createdAt: Long?) {
        val params = KeyDerivation.newParams()
        val kek = KeyDerivation.deriveKek(masterPassword, params)
        prefs.writeEnvelope(
            params = params,
            wrappedDek = CryptoManager.wrapKey(dek, kek, AAD_PASSWORD_DEK),
            createdAt = createdAt ?: System.currentTimeMillis()
        )
        // A restored vault must re-enrol biometrics on this device.
        disableBiometric()
    }

    // ── Unlock ─────────────────────────────────────────────────────────────

    /**
     * Returns the DEK, or null if the password is wrong. Wrongness is detected by
     * the GCM auth tag on the wrapped DEK failing to verify — there is no separate
     * verifier token to leak, and no way to test a password without doing the KDF.
     */
    fun unlockWithPassword(masterPassword: CharArray): SecretKey? {
        val wrapped = prefs.readWrappedDek() ?: return null
        val kek = KeyDerivation.deriveKek(masterPassword, prefs.readKdfParams())
        return try {
            CryptoManager.unwrapKey(wrapped, kek, AAD_PASSWORD_DEK)
        } catch (e: Exception) {
            null
        }
    }

    /** Re-derives the pre-envelope key so a legacy vault can be read once. */
    fun deriveLegacyKey(masterPassword: CharArray): SecretKey? {
        val verifier = prefs.readLegacyVerifier() ?: return null
        val key = KeyDerivation.deriveKek(masterPassword, prefs.readLegacyKdfParams())
        return try {
            if (CryptoManager.openLegacy(verifier, key) == LEGACY_VERIFY_TOKEN) key else null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * First commit of the v1 -> v2 migration: makes a DEK durable while leaving the
     * legacy salt in place so the old rows stay readable if this is interrupted.
     */
    fun beginLegacyMigration(masterPassword: CharArray): SecretKey {
        val dek = CryptoManager.newDataKey()
        val params = KeyDerivation.newParams()
        val kek = KeyDerivation.deriveKek(masterPassword, params)
        prefs.writeEnvelope(
            params = params,
            wrappedDek = CryptoManager.wrapKey(dek, kek, AAD_PASSWORD_DEK),
            createdAt = System.currentTimeMillis(),
            keepLegacyMaterial = true
        )
        return dek
    }

    /** Second commit: the rows are re-sealed, so the legacy key can go. */
    fun finishLegacyMigration() = prefs.clearLegacyMaterial()

    // ── Master password change ─────────────────────────────────────────────

    /**
     * Re-wraps the DEK under a new password. Record ciphertext is untouched, so
     * this cannot corrupt the vault even if it is interrupted: either the old
     * envelope or the new one is on disk, and both open the same DEK.
     */
    fun changeMasterPassword(current: CharArray, new: CharArray): Boolean {
        val dek = unlockWithPassword(current) ?: return false
        val params = KeyDerivation.newParams()
        val kek = KeyDerivation.deriveKek(new, params)
        prefs.writeEnvelope(
            params = params,
            wrappedDek = CryptoManager.wrapKey(dek, kek, AAD_PASSWORD_DEK),
            createdAt = null
        )
        return true
    }

    // ── Biometric envelope ─────────────────────────────────────────────────

    /** A cipher to hand to BiometricPrompt when enrolling this device's biometrics. */
    fun biometricEnrollmentCipher(): Cipher = biometricGuard.createEnrollmentCipher()

    /** Called after the enrollment prompt succeeds; seals the DEK under the Keystore key. */
    fun completeBiometricEnrollment(dek: SecretKey, authorisedCipher: Cipher) {
        val blob = authorisedCipher.doFinal(dek.encoded)
        prefs.writeBiometricEnvelope(
            wrappedDek = Base64.encodeToString(blob, Base64.NO_WRAP),
            iv = authorisedCipher.iv
        )
    }

    /** A cipher to hand to BiometricPrompt when unlocking, or null if re-enrollment is needed. */
    fun biometricUnlockCipher(): Cipher? {
        val (_, iv) = prefs.readBiometricEnvelope() ?: return null
        return biometricGuard.createUnlockCipher(iv)
    }

    /** Called after the unlock prompt succeeds; returns the DEK. */
    fun completeBiometricUnlock(authorisedCipher: Cipher): SecretKey? {
        val (blob, _) = prefs.readBiometricEnvelope() ?: return null
        return try {
            val raw = authorisedCipher.doFinal(Base64.decode(blob, Base64.NO_WRAP))
            CryptoManager.keyFromBytes(raw)
        } catch (e: Exception) {
            null
        }
    }

    fun disableBiometric() {
        prefs.clearBiometricEnvelope()
        biometricGuard.deleteKey()
    }

    /** True when the envelope exists but the Keystore key behind it does not. */
    fun biometricNeedsReenrollment(): Boolean =
        prefs.biometricEnabled && !biometricGuard.hasKey()
}

/** The token a pre-envelope vault encrypted to prove the password was right. */
internal const val LEGACY_VERIFY_TOKEN = "SAFE_VAULT_OK"
