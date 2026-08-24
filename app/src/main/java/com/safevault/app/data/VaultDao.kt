package com.safevault.app.data

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
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

    /**
     * Replaces the whole vault in one transaction — a restore either lands
     * completely or not at all, never leaving a half-imported vault behind.
     */
    @Transaction
    suspend fun replaceAll(entries: List<VaultEntry>) {
        deleteAll()
        upsertAll(entries)
    }
}
