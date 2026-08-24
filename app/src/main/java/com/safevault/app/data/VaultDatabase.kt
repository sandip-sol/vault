package com.safevault.app.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [VaultEntry::class, VaultService::class, UriBinding::class, PasskeyCredential::class],
    version = 4,
    exportSchema = true
)
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

        /**
         * v2 -> v3: promotes the `serviceName` text column into a real `services`
         * table, and gives a service somewhere to keep the package names and web
         * hosts that autofill matches on (`uri_bindings`).
         *
         * Every statement here is additive or a back-fill; nothing drops a column
         * or a row. `serviceName` stays on `entries` as the denormalised display
         * copy — see the note on [VaultEntry.serviceName].
         *
         * Two things are deliberately *not* done here:
         *
         *  - Bindings are not derived from the `website` column in SQL. Turning a
         *    URL into a host is [com.safevault.app.autofill.UriNormalizer]'s job,
         *    and a second, cruder implementation in SQLite string functions is
         *    exactly how a fill ends up on the wrong domain. The back-fill runs in
         *    Kotlin at first unlock — see [ServiceBackfill].
         *  - Nothing is re-encrypted. This migration touches no ciphertext, so it
         *    needs no vault key and can run before unlock.
         */
        // Visible to tests: VaultDatabaseMigrationTest builds a real v2 database
        // from the exported 2.json schema and replays this against it.
        @androidx.annotation.VisibleForTesting
        internal val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `services` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`name` TEXT NOT NULL COLLATE NOCASE, " +
                        "`createdAt` INTEGER NOT NULL, " +
                        "`updatedAt` INTEGER NOT NULL)"
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_services_name` " +
                        "ON `services` (`name`)"
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `uri_bindings` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`serviceId` INTEGER NOT NULL, " +
                        "`kind` INTEGER NOT NULL, " +
                        "`value` TEXT NOT NULL, " +
                        "`source` INTEGER NOT NULL, " +
                        "`createdAt` INTEGER NOT NULL, " +
                        "FOREIGN KEY(`serviceId`) REFERENCES `services`(`id`) " +
                        "ON UPDATE NO ACTION ON DELETE CASCADE )"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_uri_bindings_serviceId` " +
                        "ON `uri_bindings` (`serviceId`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_uri_bindings_value` " +
                        "ON `uri_bindings` (`value`)"
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS " +
                        "`index_uri_bindings_serviceId_kind_value` " +
                        "ON `uri_bindings` (`serviceId`, `kind`, `value`)"
                )

                db.execSQL("ALTER TABLE entries ADD COLUMN serviceId INTEGER NOT NULL DEFAULT 0")
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_entries_serviceId` " +
                        "ON `entries` (`serviceId`)"
                )

                // An entry with no service already displays under its title — the
                // list falls back to it. Making that explicit costs nothing
                // visually and means every credential is addressable by autofill
                // rather than only the grouped ones.
                db.execSQL("UPDATE entries SET serviceName = title WHERE serviceName = ''")

                val now = System.currentTimeMillis()
                db.execSQL(
                    "INSERT OR IGNORE INTO services (name, createdAt, updatedAt) " +
                        "SELECT DISTINCT serviceName, $now, $now FROM entries " +
                        "WHERE serviceName != ''"
                )
                db.execSQL(
                    "UPDATE entries SET serviceId = COALESCE(" +
                        "(SELECT s.id FROM services s WHERE s.name = entries.serviceName), 0)"
                )
            }
        }

        /**
         * v3 -> v4: adds passkeys as their own encrypted secret type.
         *
         * Passkeys hang off services for the same reason URI bindings do: one
         * relying party can have multiple accounts, and a service already owns
         * the user's grouping decision. The RP ID and credential ID are query
         * metadata; the private key and user handle are sealed under the vault
         * DEK with passkey-specific AAD in [VaultRepository].
         */
        @androidx.annotation.VisibleForTesting
        internal val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `passkeys` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`serviceId` INTEGER NOT NULL, " +
                        "`rpId` TEXT NOT NULL, " +
                        "`credentialId` TEXT NOT NULL, " +
                        "`username` TEXT NOT NULL, " +
                        "`displayName` TEXT NOT NULL, " +
                        "`encryptedUserHandle` TEXT NOT NULL, " +
                        "`encryptedPrivateKey` TEXT NOT NULL, " +
                        "`signCount` INTEGER NOT NULL, " +
                        "`createdAt` INTEGER NOT NULL, " +
                        "`updatedAt` INTEGER NOT NULL, " +
                        "`lastUsedAt` INTEGER NOT NULL, " +
                        "`payloadSchema` INTEGER NOT NULL, " +
                        "FOREIGN KEY(`serviceId`) REFERENCES `services`(`id`) " +
                        "ON UPDATE NO ACTION ON DELETE CASCADE )"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_passkeys_serviceId` " +
                        "ON `passkeys` (`serviceId`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_passkeys_rpId` " +
                        "ON `passkeys` (`rpId`)"
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_passkeys_credentialId` " +
                        "ON `passkeys` (`credentialId`)"
                )
            }
        }

        fun get(context: Context): VaultDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    VaultDatabase::class.java,
                    "safe_vault.db"
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
                    .build()
                    .also { INSTANCE = it }
            }
    }
}
