package com.safevault.app.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(entities = [VaultEntry::class], version = 2, exportSchema = false)
abstract class VaultDatabase : RoomDatabase() {

    abstract fun vaultDao(): VaultDao

    companion object {
        @Volatile private var INSTANCE: VaultDatabase? = null

        /**
         * v1 -> v2: adds grouping, favourites, health metadata and the encrypted
         * notes column. Purely additive with defaults, so no row can be dropped.
         * The *content* migration — re-sealing v1 payloads under the envelope DEK
         * and encrypting the plaintext `notes` column — needs the vault key and so
         * runs at first unlock, in [com.safevault.app.security.LegacyVaultMigration].
         */
        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE entries ADD COLUMN serviceName TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE entries ADD COLUMN encryptedNotes TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE entries ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE entries ADD COLUMN reuseHash TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE entries ADD COLUMN strengthScore INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE entries ADD COLUMN passwordUpdatedAt INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE entries ADD COLUMN createdAt INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE entries ADD COLUMN lastUsedAt INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE entries ADD COLUMN payloadSchema INTEGER NOT NULL DEFAULT 1")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_entries_serviceName ON entries(serviceName)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_entries_favorite ON entries(favorite)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_entries_reuseHash ON entries(reuseHash)")
                db.execSQL("UPDATE entries SET createdAt = updatedAt WHERE createdAt = 0")
                db.execSQL("UPDATE entries SET passwordUpdatedAt = updatedAt WHERE passwordUpdatedAt = 0")
            }
        }

        fun get(context: Context): VaultDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    VaultDatabase::class.java,
                    "safe_vault.db"
                )
                    .addMigrations(MIGRATION_1_2)
                    .build()
                    .also { INSTANCE = it }
            }
    }
}
