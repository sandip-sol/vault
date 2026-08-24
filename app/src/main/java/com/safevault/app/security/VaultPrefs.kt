package com.safevault.app.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Vault metadata: KDF parameters, the wrapped data-encryption key, and local
 * settings. Held in EncryptedSharedPreferences (Keystore-backed) as defence in
 * depth — nothing here is plaintext-sensitive on its own, because the DEK is
 * already wrapped by a password-derived KEK before it is written.
 *
 * The master password is never stored, in any form.
 */
class VaultPrefs(context: Context) {

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        FILE_NAME,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        const val FILE_NAME = "vault_secure_prefs"

        // Envelope-era keys
        private const val KEY_VAULT_VERSION = "vault_version"
        private const val KEY_KDF_VERSION = "kdf_version"
        private const val KEY_KDF_ITERATIONS = "kdf_iterations"
        private const val KEY_KDF_SALT = "kdf_salt"
        private const val KEY_WRAPPED_DEK = "wrapped_dek"
        private const val KEY_BIO_WRAPPED_DEK = "bio_wrapped_dek"
        private const val KEY_BIO_IV = "bio_iv"
        private const val KEY_BIOMETRIC = "biometric_enabled"
        private const val KEY_AUTO_LOCK_MS = "auto_lock_ms"
        private const val KEY_LAST_BACKUP_AT = "last_backup_at"
        private const val KEY_LAST_CONNECTED_BACKUP_AT = "last_connected_backup_at"
        private const val KEY_VAULT_CREATED_AT = "vault_created_at"
        private const val KEY_NETWORK_POLICY_MODE = "network_policy_mode"
        private const val KEY_CONNECTED_BACKUP_ENDPOINT = "connected_backup_endpoint"
        private const val KEY_CONNECTED_BACKUP_CONSENT_AT = "connected_backup_consent_at"

        // Pre-envelope (schema v1) keys, read only during migration
        private const val KEY_LEGACY_SALT = "salt"
        private const val KEY_LEGACY_VERIFIER = "verifier"

        const val VAULT_VERSION_LEGACY = 1
        const val VAULT_VERSION_ENVELOPE = 2

        val AUTO_LOCK_CHOICES_MS = longArrayOf(30_000, 60_000, 180_000, 300_000)
        const val DEFAULT_AUTO_LOCK_MS = 60_000L
    }

    // ── Vault state ────────────────────────────────────────────────────────

    /** A vault exists in either the legacy or the envelope layout. */
    val isInitialized: Boolean
        get() = prefs.contains(KEY_WRAPPED_DEK) || prefs.contains(KEY_LEGACY_VERIFIER)

    /** Created before the envelope key hierarchy; needs [LegacyVaultMigration]. */
    val isLegacyVault: Boolean
        get() = !prefs.contains(KEY_WRAPPED_DEK) && prefs.contains(KEY_LEGACY_VERIFIER)

    /**
     * Both envelopes are present, which only happens between the two commits of
     * [LegacyVaultMigration]: the DEK is durable but the rows may not all be
     * re-sealed yet. Resuming is safe because both keys are still derivable from
     * the master password.
     */
    val isMigrationIncomplete: Boolean
        get() = prefs.contains(KEY_WRAPPED_DEK) && prefs.contains(KEY_LEGACY_VERIFIER)

    val vaultCreatedAt: Long get() = prefs.getLong(KEY_VAULT_CREATED_AT, 0L)

    // ── KDF parameters ─────────────────────────────────────────────────────

    fun readKdfParams(): KeyDerivation.KdfParams = KeyDerivation.KdfParams(
        version = prefs.getInt(KEY_KDF_VERSION, KeyDerivation.CURRENT_VERSION),
        iterations = prefs.getInt(KEY_KDF_ITERATIONS, KeyDerivation.VAULT_ITERATIONS),
        salt = decode(KEY_KDF_SALT) ?: error("Vault has no KDF salt")
    )

    /** The salt from a pre-envelope vault, used once to re-derive the old key. */
    fun readLegacyKdfParams(): KeyDerivation.KdfParams = KeyDerivation.KdfParams(
        version = KeyDerivation.VERSION_PBKDF2_SHA256,
        iterations = KeyDerivation.VAULT_ITERATIONS,
        salt = decode(KEY_LEGACY_SALT) ?: error("Legacy vault has no salt")
    )

    fun readLegacyVerifier(): String? = prefs.getString(KEY_LEGACY_VERIFIER, null)

    // ── Wrapped DEK ────────────────────────────────────────────────────────

    fun readWrappedDek(): String? = prefs.getString(KEY_WRAPPED_DEK, null)

    /**
     * Writes KDF params and the password-wrapped DEK as one atomic commit.
     *
     * [keepLegacyMaterial] is set while migrating a v1 vault: the DEK must be
     * durable *before* the rows are re-sealed (or a crash would orphan them), but
     * the legacy salt has to survive until that swap commits (or a crash would
     * leave v1 rows with no key that can read them). Holding both for the length
     * of the migration is what makes it resumable.
     */
    fun writeEnvelope(
        params: KeyDerivation.KdfParams,
        wrappedDek: String,
        createdAt: Long?,
        keepLegacyMaterial: Boolean = false
    ) {
        prefs.edit().apply {
            putInt(KEY_VAULT_VERSION, VAULT_VERSION_ENVELOPE)
            putInt(KEY_KDF_VERSION, params.version)
            putInt(KEY_KDF_ITERATIONS, params.iterations)
            putString(KEY_KDF_SALT, encode(params.salt))
            putString(KEY_WRAPPED_DEK, wrappedDek)
            if (createdAt != null) putLong(KEY_VAULT_CREATED_AT, createdAt)
            if (!keepLegacyMaterial) {
                remove(KEY_LEGACY_SALT)
                remove(KEY_LEGACY_VERIFIER)
            }
        }.commit()
    }

    /** The migration's commit point: after this the vault is envelope-only. */
    fun clearLegacyMaterial() {
        prefs.edit().remove(KEY_LEGACY_SALT).remove(KEY_LEGACY_VERIFIER).commit()
    }

    // ── Biometric envelope ─────────────────────────────────────────────────

    var biometricEnabled: Boolean
        get() = prefs.getBoolean(KEY_BIOMETRIC, false)
        set(value) = prefs.edit().putBoolean(KEY_BIOMETRIC, value).apply()

    fun readBiometricEnvelope(): Pair<String, ByteArray>? {
        val blob = prefs.getString(KEY_BIO_WRAPPED_DEK, null) ?: return null
        val iv = decode(KEY_BIO_IV) ?: return null
        return blob to iv
    }

    fun writeBiometricEnvelope(wrappedDek: String, iv: ByteArray) {
        prefs.edit()
            .putString(KEY_BIO_WRAPPED_DEK, wrappedDek)
            .putString(KEY_BIO_IV, encode(iv))
            .putBoolean(KEY_BIOMETRIC, true)
            .commit()
    }

    fun clearBiometricEnvelope() {
        prefs.edit()
            .remove(KEY_BIO_WRAPPED_DEK)
            .remove(KEY_BIO_IV)
            .putBoolean(KEY_BIOMETRIC, false)
            .commit()
    }

    // ── Settings ───────────────────────────────────────────────────────────

    var autoLockMs: Long
        get() = prefs.getLong(KEY_AUTO_LOCK_MS, DEFAULT_AUTO_LOCK_MS)
        set(value) = prefs.edit().putLong(KEY_AUTO_LOCK_MS, value).apply()

    var lastBackupAt: Long
        get() = prefs.getLong(KEY_LAST_BACKUP_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_BACKUP_AT, value).apply()

    var lastConnectedBackupAt: Long
        get() = prefs.getLong(KEY_LAST_CONNECTED_BACKUP_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_CONNECTED_BACKUP_AT, value).apply()

    var networkPolicyMode: NetworkPolicy.Mode
        get() {
            val stored = prefs.getString(KEY_NETWORK_POLICY_MODE, null) ?: return NetworkPolicy.Mode.DENY_ALL
            return runCatching { NetworkPolicy.Mode.valueOf(stored) }
                .getOrDefault(NetworkPolicy.Mode.DENY_ALL)
        }
        set(value) = prefs.edit().putString(KEY_NETWORK_POLICY_MODE, value.name).apply()

    var connectedBackupEndpoint: String
        get() = prefs.getString(KEY_CONNECTED_BACKUP_ENDPOINT, "") ?: ""
        set(value) = prefs.edit().putString(KEY_CONNECTED_BACKUP_ENDPOINT, value.trim()).apply()

    val connectedBackupConsentAt: Long
        get() = prefs.getLong(KEY_CONNECTED_BACKUP_CONSENT_AT, 0L)

    fun enableConnectedBackup(endpoint: String, consentAt: Long = System.currentTimeMillis()) {
        prefs.edit()
            .putString(KEY_NETWORK_POLICY_MODE, NetworkPolicy.Mode.CONNECTED_BACKUP_ONLY.name)
            .putString(KEY_CONNECTED_BACKUP_ENDPOINT, endpoint.trim())
            .putLong(KEY_CONNECTED_BACKUP_CONSENT_AT, consentAt)
            .apply()
    }

    fun disableConnectedBackup() {
        prefs.edit()
            .putString(KEY_NETWORK_POLICY_MODE, NetworkPolicy.Mode.DENY_ALL.name)
            .remove(KEY_CONNECTED_BACKUP_ENDPOINT)
            .remove(KEY_CONNECTED_BACKUP_CONSENT_AT)
            .apply()
    }

    fun networkPolicySettings() = NetworkPolicy.Settings(
        mode = networkPolicyMode,
        connectedBackupConsentAt = connectedBackupConsentAt,
        connectedBackupEndpoint = connectedBackupEndpoint
    )

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(key: String): ByteArray? =
        prefs.getString(key, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
}
