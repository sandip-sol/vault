package com.safevault.app.data

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface VaultDao {

    @Query("SELECT * FROM entries ORDER BY serviceName COLLATE NOCASE ASC, title COLLATE NOCASE ASC")
    fun observeAll(): Flow<List<VaultEntry>>

    @Query("SELECT * FROM entries ORDER BY lastUsedAt DESC LIMIT :limit")
    fun observeRecent(limit: Int): Flow<List<VaultEntry>>

    @Query("SELECT * FROM entries")
    suspend fun getAll(): List<VaultEntry>

    @Query("SELECT * FROM entries WHERE id = :id")
    suspend fun getById(id: Long): VaultEntry?

    @Query("SELECT COUNT(*) FROM entries")
    suspend fun count(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: VaultEntry): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<VaultEntry>)

    @Delete
    suspend fun delete(entry: VaultEntry)

    @Query("DELETE FROM entries")
    suspend fun deleteAll()

    @Query("UPDATE entries SET favorite = :favorite WHERE id = :id")
    suspend fun setFavorite(id: Long, favorite: Boolean)

    @Query("UPDATE entries SET lastUsedAt = :at WHERE id = :id")
    suspend fun markUsed(id: Long, at: Long)

    // ── Services ───────────────────────────────────────────────────────────

    @Query("SELECT * FROM services ORDER BY name COLLATE NOCASE ASC")
    suspend fun allServices(): List<VaultService>

    @Query("SELECT * FROM services WHERE id = :id")
    suspend fun serviceById(id: Long): VaultService?

    /** NOCASE on the column makes this the same lookup the unique index enforces. */
    @Query("SELECT * FROM services WHERE name = :name LIMIT 1")
    suspend fun serviceByName(name: String): VaultService?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertService(service: VaultService): Long

    @Update
    suspend fun updateService(service: VaultService)

    @Query("DELETE FROM services WHERE id NOT IN (SELECT DISTINCT serviceId FROM entries)")
    suspend fun deleteOrphanServices(): Int

    // ── URI bindings ───────────────────────────────────────────────────────

    @Query("SELECT * FROM uri_bindings WHERE serviceId = :serviceId ORDER BY kind ASC, value ASC")
    suspend fun bindingsFor(serviceId: Long): List<UriBinding>

    @Query("SELECT * FROM uri_bindings")
    suspend fun allBindings(): List<UriBinding>

    /**
     * The autofill lookup. The caller expands a request host into the exact set
     * of hosts a binding is allowed to match — the host itself and each parent
     * up to the registrable domain — so this stays an indexed equality search
     * and the suffix rule is never re-implemented in SQL.
     */
    @Query("SELECT * FROM uri_bindings WHERE kind = :kind AND value IN (:values)")
    suspend fun findBindings(kind: Int, values: List<String>): List<UriBinding>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertBinding(binding: UriBinding): Long

    @Query("DELETE FROM uri_bindings WHERE id = :id")
    suspend fun deleteBinding(id: Long)

    @Query("DELETE FROM uri_bindings")
    suspend fun deleteAllBindings()

    @Query("DELETE FROM services")
    suspend fun deleteAllServices()

    // ── Passkeys ──────────────────────────────────────────────────────────

    @Query("SELECT * FROM passkeys")
    suspend fun allPasskeys(): List<PasskeyCredential>

    @Query("SELECT * FROM passkeys WHERE id = :id")
    suspend fun passkeyById(id: Long): PasskeyCredential?

    @Query("SELECT * FROM passkeys WHERE credentialId = :credentialId LIMIT 1")
    suspend fun passkeyByCredentialId(credentialId: String): PasskeyCredential?

    @Query("SELECT * FROM passkeys WHERE rpId = :rpId ORDER BY lastUsedAt DESC, username COLLATE NOCASE ASC")
    suspend fun passkeysForRpId(rpId: String): List<PasskeyCredential>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPasskey(passkey: PasskeyCredential): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPasskeys(passkeys: List<PasskeyCredential>)

    @Query("UPDATE passkeys SET lastUsedAt = :at, signCount = signCount + 1 WHERE id = :id")
    suspend fun markPasskeyUsed(id: Long, at: Long)

    @Query("DELETE FROM passkeys")
    suspend fun deleteAllPasskeys()

    // ── Entries by service ─────────────────────────────────────────────────

    @Query("SELECT * FROM entries WHERE serviceId IN (:serviceIds)")
    suspend fun entriesForServices(serviceIds: List<Long>): List<VaultEntry>

    @Query("SELECT * FROM entries WHERE website != ''")
    suspend fun entriesWithWebsite(): List<VaultEntry>

    @Query("UPDATE entries SET serviceId = :serviceId WHERE id = :id")
    suspend fun setServiceId(id: Long, serviceId: Long)

    /**
     * Rewrites every entry row, leaving services and bindings alone.
     *
     * This is the re-seal path: [com.safevault.app.security.LegacyVaultMigration]
     * re-encrypts the same credentials under a new key and puts them back. The
     * services they belong to are unchanged by that, and dropping them would
     * discard bindings the vault has no way to rebuild.
     */
    @Transaction
    suspend fun replaceAll(entries: List<VaultEntry>) {
        deleteAll()
        upsertAll(entries)
    }

    /**
     * Replaces the whole vault in one transaction — a restore either lands
     * completely or not at all, never leaving a half-imported vault behind.
     */
    @Transaction
    suspend fun replaceVault(
        entries: List<VaultEntry>,
        services: List<VaultService>,
        bindings: List<UriBinding>,
        passkeys: List<PasskeyCredential>
    ) {
        // Bindings cascade from services, but the delete order still matters:
        // entries reference services by a plain column, not a foreign key, so
        // clearing entries first means no row ever points at a service that has
        // already gone.
        deleteAll()
        deleteAllPasskeys()
        deleteAllBindings()
        deleteAllServices()
        insertServices(services)
        insertBindings(bindings)
        insertPasskeys(passkeys)
        upsertAll(entries)
    }

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertServices(services: List<VaultService>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertBindings(bindings: List<UriBinding>)
}
