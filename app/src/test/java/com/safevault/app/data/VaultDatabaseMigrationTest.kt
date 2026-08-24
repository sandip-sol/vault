package com.safevault.app.data

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * Replays the 2 -> 3 migration against a real database built from the real v2
 * schema.
 *
 * The roadmap's first testing gap was that migrations were verified by hand on a
 * device, while "a migration that can silently drop or corrupt records" sits on
 * the release-blocker list. Hand-verification cannot support that claim: it shows
 * the migration worked once, on one vault, on one device.
 *
 * The v2 table definitions are read from `schemas/…/2.json` — the schema Room
 * itself exported while the database was at version 2 — rather than written out
 * again here. A migration test whose "before" state is hand-typed tests the
 * migration against the schema the author *believed* was live, which is the
 * belief that produces broken migrations in the first place.
 */
@RunWith(RobolectricTestRunner::class)
class VaultDatabaseMigrationTest {

    private var helper: SupportSQLiteOpenHelper? = null

    @After
    fun tearDown() {
        helper?.close()
    }

    // ── Fixture ────────────────────────────────────────────────────────────

    private fun schemaFile(version: Int): File {
        val relative = "schemas/com.safevault.app.data.VaultDatabase/$version.json"
        // Gradle runs unit tests with the module directory as the working
        // directory, but that is a convention rather than a guarantee.
        val candidates = listOf(File(relative), File("app/$relative"))
        return candidates.firstOrNull { it.isFile }
            ?: error("Exported schema $version.json not found (looked in $candidates)")
    }

    /** Creates an empty database at schema version 2, exactly as Room defined it. */
    private fun openAtV2(): SupportSQLiteDatabase {
        val schema = JSONObject(schemaFile(2).readText())
        val entities = schema.getJSONObject("database").getJSONArray("entities")

        val callback = object : SupportSQLiteOpenHelper.Callback(2) {
            override fun onCreate(db: SupportSQLiteDatabase) {
                for (i in 0 until entities.length()) {
                    val entity = entities.getJSONObject(i)
                    val table = entity.getString("tableName")
                    db.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", table))
                    val indices = entity.optJSONArray("indices") ?: continue
                    for (j in 0 until indices.length()) {
                        db.execSQL(
                            indices.getJSONObject(j).getString("createSql")
                                .replace("\${TABLE_NAME}", table)
                        )
                    }
                }
            }

            override fun onUpgrade(db: SupportSQLiteDatabase, old: Int, new: Int) = Unit
        }

        val config = SupportSQLiteOpenHelper.Configuration
            .builder(ApplicationProvider.getApplicationContext())
            .name(null) // in-memory
            .callback(callback)
            .build()

        return FrameworkSQLiteOpenHelperFactory().create(config)
            .also { helper = it }
            .writableDatabase
    }

    private fun insertV2Entry(
        db: SupportSQLiteDatabase,
        title: String,
        serviceName: String,
        website: String = ""
    ) {
        db.execSQL(
            "INSERT INTO entries (title, serviceName, website, encryptedUsername, " +
                "encryptedPassword, encryptedNotes, notes, favorite, reuseHash, " +
                "strengthScore, passwordUpdatedAt, createdAt, updatedAt, lastUsedAt, " +
                "payloadSchema) VALUES (?, ?, ?, 'v2.user', 'v2.pass', '', '', 0, '', " +
                "3, 0, 0, 0, 0, 2)",
            arrayOf(title, serviceName, website)
        )
    }

    private fun SupportSQLiteDatabase.rows(sql: String): List<List<String?>> =
        query(sql).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add((0 until c.columnCount).map { if (c.isNull(it)) null else c.getString(it) })
                }
            }
        }

    private fun SupportSQLiteDatabase.orphanedEntries(): List<String?> = rows(
        "SELECT e.title FROM entries e " +
            "LEFT JOIN services s ON s.id = e.serviceId WHERE s.id IS NULL"
    ).map { it[0] }

    // ── Tests ──────────────────────────────────────────────────────────────

    @Test
    fun `migration keeps every entry`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Google", "https://mail.google.com")
        insertV2Entry(db, "Work", "Google", "https://accounts.google.com")
        insertV2Entry(db, "GitHub", "GitHub", "github.com")
        insertV2Entry(db, "Ungrouped", "", "")

        VaultDatabase.MIGRATION_2_3.migrate(db)

        assertEquals(4, db.rows("SELECT id FROM entries").size)
        assertEquals(
            listOf("GitHub", "Personal", "Ungrouped", "Work"),
            db.rows("SELECT title FROM entries ORDER BY title").map { it[0] }
        )
    }

    @Test
    fun `migration preserves the encrypted columns untouched`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Google")

        VaultDatabase.MIGRATION_2_3.migrate(db)

        val row = db.rows("SELECT encryptedUsername, encryptedPassword FROM entries").single()
        assertEquals(listOf("v2.user", "v2.pass"), row)
    }

    @Test
    fun `every entry ends up pointing at a service that exists`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Google")
        insertV2Entry(db, "Work", "Google")
        insertV2Entry(db, "GitHub", "GitHub")

        VaultDatabase.MIGRATION_2_3.migrate(db)

        assertTrue("entries left without a service: ${db.orphanedEntries()}", db.orphanedEntries().isEmpty())
    }

    @Test
    fun `accounts sharing a service name collapse to one service`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Google")
        insertV2Entry(db, "Work", "Google")

        VaultDatabase.MIGRATION_2_3.migrate(db)

        assertEquals(1, db.rows("SELECT id FROM services").size)
        assertEquals(1, db.rows("SELECT DISTINCT serviceId FROM entries").size)
    }

    @Test
    fun `service names differing only in case are one service`() {
        // The unique index is NOCASE, so the INSERT ... SELECT DISTINCT must not
        // be able to create "GitHub" and "github" as two rows — and the entry
        // back-fill must still find a service for both spellings.
        val db = openAtV2()
        insertV2Entry(db, "One", "GitHub")
        insertV2Entry(db, "Two", "github")

        VaultDatabase.MIGRATION_2_3.migrate(db)

        assertEquals(1, db.rows("SELECT id FROM services").size)
        assertTrue("case-variant entry lost its service: ${db.orphanedEntries()}", db.orphanedEntries().isEmpty())
    }

    @Test
    fun `an ungrouped entry is filed under its own title`() {
        val db = openAtV2()
        insertV2Entry(db, "Lone Account", "")

        VaultDatabase.MIGRATION_2_3.migrate(db)

        assertEquals(listOf("Lone Account"), db.rows("SELECT name FROM services").map { it[0] })
        assertEquals(listOf("Lone Account"), db.rows("SELECT serviceName FROM entries").map { it[0] })
        assertTrue(db.orphanedEntries().isEmpty())
    }

    @Test
    fun `the new tables and indices exist afterwards`() {
        val db = openAtV2()
        VaultDatabase.MIGRATION_2_3.migrate(db)

        val tables = db.rows("SELECT name FROM sqlite_master WHERE type = 'table'").map { it[0] }
        assertTrue("actual tables: $tables", tables.containsAll(listOf("entries", "services", "uri_bindings")))

        val indices = db.rows("SELECT name FROM sqlite_master WHERE type = 'index'").map { it[0] }
        assertTrue(
            "missing indices, actual: $indices",
            indices.containsAll(
                listOf(
                    "index_services_name",
                    "index_uri_bindings_serviceId",
                    "index_uri_bindings_value",
                    "index_uri_bindings_serviceId_kind_value",
                    "index_entries_serviceId"
                )
            )
        )
    }

    @Test
    fun `bindings cascade when their service is deleted`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Google")
        VaultDatabase.MIGRATION_2_3.migrate(db)
        db.execSQL("PRAGMA foreign_keys = ON")

        val serviceId = db.rows("SELECT id FROM services").first()[0]
        db.execSQL(
            "INSERT INTO uri_bindings (serviceId, kind, value, source, createdAt) " +
                "VALUES (?, 0, 'google.com', 1, 0)",
            arrayOf(serviceId)
        )
        assertEquals(1, db.rows("SELECT id FROM uri_bindings").size)

        db.execSQL("DELETE FROM services WHERE id = ?", arrayOf(serviceId))
        assertEquals(0, db.rows("SELECT id FROM uri_bindings").size)
    }

    @Test
    fun `the unique binding index rejects a duplicate`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Google")
        VaultDatabase.MIGRATION_2_3.migrate(db)

        val serviceId = db.rows("SELECT id FROM services").first()[0]
        repeat(2) {
            db.execSQL(
                "INSERT OR IGNORE INTO uri_bindings (serviceId, kind, value, source, createdAt) " +
                    "VALUES (?, 0, 'google.com', 1, 0)",
                arrayOf(serviceId)
            )
        }
        assertEquals(1, db.rows("SELECT id FROM uri_bindings").size)
    }

    @Test
    fun `an empty vault migrates without error`() {
        val db = openAtV2()
        VaultDatabase.MIGRATION_2_3.migrate(db)

        assertEquals(0, db.rows("SELECT id FROM entries").size)
        assertEquals(0, db.rows("SELECT id FROM services").size)
        assertEquals(0, db.rows("SELECT id FROM uri_bindings").size)
    }

    @Test
    fun `phase five migration adds passkey table and indices`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Example")
        VaultDatabase.MIGRATION_2_3.migrate(db)
        VaultDatabase.MIGRATION_3_4.migrate(db)

        val tables = db.rows("SELECT name FROM sqlite_master WHERE type = 'table'").map { it[0] }
        assertTrue("actual tables: $tables", tables.contains("passkeys"))

        val indices = db.rows("SELECT name FROM sqlite_master WHERE type = 'index'").map { it[0] }
        assertTrue(
            "missing passkey indices, actual: $indices",
            indices.containsAll(
                listOf(
                    "index_passkeys_serviceId",
                    "index_passkeys_rpId",
                    "index_passkeys_credentialId"
                )
            )
        )
    }

    @Test
    fun `passkeys cascade when their service is deleted`() {
        val db = openAtV2()
        insertV2Entry(db, "Personal", "Example")
        VaultDatabase.MIGRATION_2_3.migrate(db)
        VaultDatabase.MIGRATION_3_4.migrate(db)
        db.execSQL("PRAGMA foreign_keys = ON")

        val serviceId = db.rows("SELECT id FROM services").first()[0]
        db.execSQL(
            "INSERT INTO passkeys (serviceId, rpId, credentialId, username, displayName, " +
                "encryptedUserHandle, encryptedPrivateKey, signCount, createdAt, updatedAt, " +
                "lastUsedAt, payloadSchema) VALUES (?, 'example.com', 'cred-1', " +
                "'user@example.com', 'User', 'v2.handle', 'v2.key', 0, 0, 0, 0, 2)",
            arrayOf(serviceId)
        )
        assertEquals(1, db.rows("SELECT id FROM passkeys").size)

        db.execSQL("DELETE FROM services WHERE id = ?", arrayOf(serviceId))
        assertEquals(0, db.rows("SELECT id FROM passkeys").size)
    }
}
