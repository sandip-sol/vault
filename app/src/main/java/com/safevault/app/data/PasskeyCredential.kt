package com.safevault.app.data

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import com.safevault.app.security.CryptoManager

/**
 * A discoverable WebAuthn credential stored by SafeVault.
 *
 * The RP ID and credential ID are lookup metadata needed before decryption. The
 * user handle and private key are secrets and are sealed by [VaultRepository]
 * with passkey-specific AAD before they ever reach this table.
 */
@Entity(
    tableName = "passkeys",
    foreignKeys = [
        ForeignKey(
            entity = VaultService::class,
            parentColumns = ["id"],
            childColumns = ["serviceId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index("serviceId"),
        Index("rpId"),
        Index(value = ["credentialId"], unique = true)
    ]
)
data class PasskeyCredential(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,

    val serviceId: Long,

    /** WebAuthn relying party ID, stored lowercase. */
    val rpId: String,

    /** Base64url(no padding) credential id. */
    val credentialId: String,

    /** Selector metadata. */
    val username: String,
    val displayName: String = "",

    val encryptedUserHandle: String,
    val encryptedPrivateKey: String,

    /** Monotonic signature counter. Sync can revisit this; local-only starts at 0. */
    val signCount: Long = 0L,

    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val lastUsedAt: Long = 0L,
    val payloadSchema: Int = CryptoManager.SCHEMA_CURRENT
)
