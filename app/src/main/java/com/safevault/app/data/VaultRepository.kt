package com.safevault.app.data

import android.content.Context
import com.safevault.app.security.CryptoManager
import com.safevault.app.security.PasswordHealth
import kotlinx.coroutines.flow.Flow
import javax.crypto.SecretKey

/** A credential as the user edits it — plaintext, never persisted in this shape. */
data class CredentialDraft(
    val id: Long = 0,
    val title: String,
    val serviceName: String,
    val website: String,
    val username: String,
    val password: String,
    val notes: String,
    val favorite: Boolean = false
)

/** A decrypted credential for display. */
data class CredentialDetail(
    val entry: VaultEntry,
    val username: String,
    val password: String,
    val notes: String
)

/**
 * The single place where vault plaintext crosses into storage. Activities deal in
 * [CredentialDraft]/[CredentialDetail] and never call the cipher themselves, so
 * there is exactly one code path to audit for "did this get encrypted".
 */
class VaultRepository(context: Context) {

    private val dao = VaultDatabase.get(context).vaultDao()

    companion object {
        /**
         * Associated data binds each ciphertext to the column it belongs in.
         * Moving a password blob into the username column makes the tag fail.
         */
        const val AAD_USERNAME = "entry/username/v2"
        const val AAD_PASSWORD = "entry/password/v2"
        const val AAD_NOTES = "entry/notes/v2"
    }

    fun observeAll(): Flow<List<VaultEntry>> = dao.observeAll()

    suspend fun count(): Int = dao.count()

    suspend fun getAll(): List<VaultEntry> = dao.getAll()

    suspend fun load(id: Long, key: SecretKey): CredentialDetail? {
        val entry = dao.getById(id) ?: return null
        return CredentialDetail(
            entry = entry,
            username = decryptField(entry.encryptedUsername, key, AAD_USERNAME),
            password = decryptField(entry.encryptedPassword, key, AAD_PASSWORD),
            notes = when {
                entry.encryptedNotes.isNotEmpty() ->
                    decryptField(entry.encryptedNotes, key, AAD_NOTES)
                // A v1 row that has not been through the content migration yet.
                else -> entry.notes
            }
        )
    }

    suspend fun save(draft: CredentialDraft, key: SecretKey): Long {
        val now = System.currentTimeMillis()
        val existing = if (draft.id > 0) dao.getById(draft.id) else null
        val passwordChanged = existing == null ||
            decryptField(existing.encryptedPassword, key, AAD_PASSWORD) != draft.password

        val entry = VaultEntry(
            id = draft.id,
            title = draft.title,
            serviceName = draft.serviceName,
            website = draft.website,
            encryptedUsername = CryptoManager.encrypt(draft.username, key, AAD_USERNAME),
            encryptedPassword = CryptoManager.encrypt(draft.password, key, AAD_PASSWORD),
            encryptedNotes = if (draft.notes.isEmpty()) ""
                else CryptoManager.encrypt(draft.notes, key, AAD_NOTES),
            notes = "",
            favorite = draft.favorite,
            reuseHash = PasswordHealth.reuseHash(draft.password, key),
            strengthScore = PasswordHealth.score(draft.password),
            passwordUpdatedAt = if (passwordChanged) now else (existing?.passwordUpdatedAt ?: now),
            createdAt = existing?.createdAt ?: now,
            updatedAt = now,
            lastUsedAt = existing?.lastUsedAt ?: 0L,
            payloadSchema = CryptoManager.SCHEMA_CURRENT
        )
        return dao.upsert(entry)
    }

    suspend fun delete(entry: VaultEntry) = dao.delete(entry)

    suspend fun setFavorite(id: Long, favorite: Boolean) = dao.setFavorite(id, favorite)

    suspend fun markUsed(id: Long) = dao.markUsed(id, System.currentTimeMillis())

    suspend fun replaceAll(entries: List<VaultEntry>) = dao.replaceAll(entries)

    /**
     * Reads a field written under either payload schema. v1 rows are readable
     * until the content migration re-seals them; after that only v2 is produced.
     */
    private fun decryptField(payload: String, key: SecretKey, aad: String): String {
        if (payload.isEmpty()) return ""
        return if (CryptoManager.isCurrentSchema(payload)) {
            CryptoManager.decrypt(payload, key, aad)
        } else {
            CryptoManager.openLegacy(payload, key)
        }
    }
}
