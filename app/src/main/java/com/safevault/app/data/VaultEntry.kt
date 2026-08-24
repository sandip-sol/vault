package com.safevault.app.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import com.safevault.app.security.CryptoManager

/**
 * One credential.
 *
 * The `encrypted*` columns hold AEAD payloads sealed under the vault DEK — the
 * database file itself is treated as untrusted storage. Everything else is
 * deliberately non-secret so the list can be rendered, searched and grouped
 * without decrypting the whole vault on every keystroke.
 *
 * [reuseHash] is a keyed digest of the password, not the password: it detects
 * reuse across entries without the vault ever storing anything reversible.
 */
@Entity(
    tableName = "entries",
    indices = [Index("serviceName"), Index("favorite"), Index("reuseHash")]
)
data class VaultEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,

    val title: String,
    /** Grouping key — several accounts on one service share this. */
    val serviceName: String = "",
    val website: String = "",

    val encryptedUsername: String,
    val encryptedPassword: String,
    val encryptedNotes: String = "",

    /** Plaintext notes from schema v1. Emptied by LegacyVaultMigration. */
    val notes: String = "",

    val favorite: Boolean = false,

    /** Keyed digest of the password; "" until computed. */
    val reuseHash: String = "",
    /** Cached [com.safevault.app.security.PasswordHealth] score, 0..4. */
    val strengthScore: Int = 0,

    val passwordUpdatedAt: Long = 0L,
    val createdAt: Long = 0L,
    val updatedAt: Long = System.currentTimeMillis(),
    val lastUsedAt: Long = 0L,

    /** Which [CryptoManager] payload schema the encrypted columns use. */
    val payloadSchema: Int = CryptoManager.SCHEMA_CURRENT
) {
    /** What the list groups under — falls back to the title for ungrouped entries. */
    val groupLabel: String get() = serviceName.ifBlank { title }
}
