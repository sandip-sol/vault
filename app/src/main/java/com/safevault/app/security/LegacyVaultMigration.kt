package com.safevault.app.security

import android.content.Context
import com.safevault.app.data.VaultDatabase
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

/**
 * Upgrades a schema-v1 vault to the envelope hierarchy, at first unlock, while
 * the master password is in hand.
 *
 * v1 encrypted every record directly under PBKDF2(master password) and left
 * notes in plaintext. v2 encrypts records under a random DEK with per-field
 * associated data, and wraps that DEK under the password. Getting from one to
 * the other means reading every row with the old key and re-sealing it with the
 * new one — which is exactly the kind of migration that must not be able to eat
 * a vault halfway through.
 *
 * It is made crash-safe by ordering the two durable writes so that at every
 * instant *some* derivable key can read the rows on disk:
 *
 *  1. Write the wrapped DEK, keeping the legacy salt.  Both keys derivable.
 *  2. Re-seal all rows in one DB transaction.          Both keys derivable.
 *  3. Drop the legacy salt.                            Only the DEK is needed.
 *
 * An interruption anywhere leaves the vault openable and the migration
 * resumable — step 2 is idempotent because each row records its own schema.
 */
object LegacyVaultMigration {

    sealed interface Result {
        /** Already on the current schema. */
        data object NotNeeded : Result
        data class Migrated(val entries: Int) : Result
        data object WrongPassword : Result
        data class Failed(val cause: Throwable) : Result
    }

    suspend fun runIfNeeded(context: Context, masterPassword: CharArray): Result =
        withContext(Dispatchers.Default) {
            val keys = VaultKeyManager(context)
            if (!keys.isLegacyVault && !keys.isMigrationIncomplete) return@withContext Result.NotNeeded

            try {
                val legacyKey = keys.deriveLegacyKey(masterPassword)
                    ?: return@withContext Result.WrongPassword

                // Resuming picks up the DEK already committed by a previous attempt.
                val dek = if (keys.isMigrationIncomplete) {
                    keys.unlockWithPassword(masterPassword)
                        ?: return@withContext Result.WrongPassword
                } else {
                    keys.beginLegacyMigration(masterPassword)
                }

                val dao = VaultDatabase.get(context).vaultDao()
                val resealed = dao.getAll().map { row -> reseal(row, legacyKey, dek) }
                dao.replaceAll(resealed)

                keys.finishLegacyMigration()
                Result.Migrated(resealed.size)
            } catch (e: Throwable) {
                Result.Failed(e)
            }
        }

    private fun reseal(row: VaultEntry, legacyKey: SecretKey, dek: SecretKey): VaultEntry {
        val username = read(row.encryptedUsername, legacyKey, dek, VaultRepository.AAD_USERNAME)
        val password = read(row.encryptedPassword, legacyKey, dek, VaultRepository.AAD_PASSWORD)
        val notes = when {
            row.encryptedNotes.isNotEmpty() ->
                CryptoManager.decrypt(row.encryptedNotes, dek, VaultRepository.AAD_NOTES)
            else -> row.notes
        }
        val stamp = if (row.updatedAt > 0) row.updatedAt else System.currentTimeMillis()

        return row.copy(
            encryptedUsername = CryptoManager.encrypt(username, dek, VaultRepository.AAD_USERNAME),
            encryptedPassword = CryptoManager.encrypt(password, dek, VaultRepository.AAD_PASSWORD),
            encryptedNotes = if (notes.isEmpty()) ""
                else CryptoManager.encrypt(notes, dek, VaultRepository.AAD_NOTES),
            notes = "",
            reuseHash = PasswordHealth.reuseHash(password, dek),
            strengthScore = PasswordHealth.score(password),
            createdAt = if (row.createdAt > 0) row.createdAt else stamp,
            passwordUpdatedAt = if (row.passwordUpdatedAt > 0) row.passwordUpdatedAt else stamp,
            payloadSchema = CryptoManager.SCHEMA_CURRENT
        )
    }

    /** A row already re-sealed by an interrupted run reads with the DEK, not the old key. */
    private fun read(payload: String, legacyKey: SecretKey, dek: SecretKey, aad: String): String {
        if (payload.isEmpty()) return ""
        return if (CryptoManager.isCurrentSchema(payload)) CryptoManager.decrypt(payload, dek, aad)
        else CryptoManager.openLegacy(payload, legacyKey)
    }
}
