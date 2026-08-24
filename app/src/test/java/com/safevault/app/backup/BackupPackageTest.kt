package com.safevault.app.backup

import com.safevault.app.data.VaultEntry
import com.safevault.app.security.CryptoManager
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BackupPackageTest {

    private val passphrase = "a-long-backup-passphrase".toCharArray()

    private fun sampleEntries(count: Int = 3) = (1..count).map { i ->
        VaultEntry(
            id = i.toLong(),
            title = "Account $i",
            serviceName = "Service ${i % 2}",
            website = "example$i.com",
            encryptedUsername = "v2.dXNlcm5hbWUtY2lwaGVydGV4dA==",
            encryptedPassword = "v2.cGFzc3dvcmQtY2lwaGVydGV4dA==",
            encryptedNotes = "",
            favorite = i == 1,
            reuseHash = "hash$i",
            strengthScore = 3,
            passwordUpdatedAt = 1_000L * i,
            createdAt = 500L * i,
            updatedAt = 2_000L * i,
            lastUsedAt = 0L
        )
    }

    @Test
    fun `round trips the vault key and every entry`() {
        val dek = CryptoManager.newDataKey()
        val entries = sampleEntries()
        val bytes = BackupPackage.write(passphrase, dek, vaultCreatedAt = 42L, entries = entries)

        val opened = BackupPackage.open(bytes, passphrase)
        assertNotNull(opened)
        opened!!

        assertTrue(dek.encoded.contentEquals(opened.dek.encoded))
        assertEquals(42L, opened.vaultCreatedAt)
        assertEquals(entries.size, opened.entries.size)
        assertEquals(entries.map { it.title }, opened.entries.map { it.title })
        assertEquals(entries.map { it.encryptedPassword }, opened.entries.map { it.encryptedPassword })
        assertEquals(entries.map { it.favorite }, opened.entries.map { it.favorite })
    }

    @Test
    fun `header is readable without the passphrase`() {
        val bytes = BackupPackage.write(passphrase, CryptoManager.newDataKey(), 0L, sampleEntries(5))
        val header = BackupPackage.readHeader(bytes)

        assertEquals(BackupPackage.VERSION, header.version)
        assertEquals(5, header.entryCount)
        assertTrue(header.createdAt > 0)
        assertTrue(header.kdf.iterations >= 310_000)
    }

    @Test
    fun `carries no plaintext of the entries`() {
        val bytes = BackupPackage.write(passphrase, CryptoManager.newDataKey(), 0L, sampleEntries())
        val text = String(bytes, Charsets.UTF_8)
        // Titles and services live inside the sealed payload, not the header.
        assertTrue("Entry titles must not appear in the clear", !text.contains("Account 1"))
        assertTrue("Service names must not appear in the clear", !text.contains("Service 1"))
    }

    @Test
    fun `wrong passphrase returns null instead of partial data`() {
        val bytes = BackupPackage.write(passphrase, CryptoManager.newDataKey(), 0L, sampleEntries())
        assertNull(BackupPackage.open(bytes, "not-the-passphrase".toCharArray()))
    }

    @Test
    fun `a tampered payload does not open`() {
        val bytes = BackupPackage.write(passphrase, CryptoManager.newDataKey(), 0L, sampleEntries())
        val json = JSONObject(String(bytes, Charsets.UTF_8))
        val payload = json.getString("payload")
        json.put("payload", payload.dropLast(3) + "AAA")

        val tampered = json.toString().toByteArray(Charsets.UTF_8)
        // Either the tag rejects it or the base64 is malformed; neither may import.
        val opened = try {
            BackupPackage.open(tampered, passphrase)
        } catch (e: Exception) {
            null
        }
        assertNull(opened)
    }

    @Test
    fun `a truncated file is rejected`() {
        val bytes = BackupPackage.write(passphrase, CryptoManager.newDataKey(), 0L, sampleEntries())
        val truncated = bytes.copyOf(bytes.size / 2)
        try {
            BackupPackage.open(truncated, passphrase)
            fail("Truncated backup should be rejected")
        } catch (e: BackupPackage.MalformedBackupException) {
            // expected
        }
    }

    @Test
    fun `a file from another app is rejected by format`() {
        val foreign = """{"format":"something.else","version":1}""".toByteArray(Charsets.UTF_8)
        try {
            BackupPackage.readHeader(foreign)
            fail("Foreign file should be rejected")
        } catch (e: BackupPackage.MalformedBackupException) {
            assertTrue(e.message!!.contains("SafeVault"))
        }
    }

    @Test
    fun `an unknown version is rejected rather than guessed at`() {
        val bytes = BackupPackage.write(passphrase, CryptoManager.newDataKey(), 0L, sampleEntries())
        val json = JSONObject(String(bytes, Charsets.UTF_8)).put("version", 99)
        try {
            BackupPackage.readHeader(json.toString().toByteArray(Charsets.UTF_8))
            fail("Unknown version should be rejected")
        } catch (e: BackupPackage.MalformedBackupException) {
            assertTrue(e.message!!.contains("99"))
        }
    }

    @Test
    fun `an entry count that disagrees with the payload is rejected`() {
        val bytes = BackupPackage.write(passphrase, CryptoManager.newDataKey(), 0L, sampleEntries(3))
        val json = JSONObject(String(bytes, Charsets.UTF_8)).put("entryCount", 2)
        try {
            BackupPackage.open(json.toString().toByteArray(Charsets.UTF_8), passphrase)
            fail("Count mismatch should be rejected")
        } catch (e: BackupPackage.MalformedBackupException) {
            // expected
        }
    }
}
