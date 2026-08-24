package com.safevault.app.backup

import com.safevault.app.data.UriBinding
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultService
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

    private fun sampleServices(count: Int = 2) = (0 until count).map { i ->
        VaultService(id = i + 1L, name = "Service $i", createdAt = 100L, updatedAt = 200L)
    }

    private fun sampleBindings() = listOf(
        UriBinding(id = 1, serviceId = 1, kind = UriBinding.KIND_WEB, value = "example1.com"),
        UriBinding(id = 2, serviceId = 1, kind = UriBinding.KIND_ANDROID_APP, value = "com.example.one"),
        UriBinding(id = 3, serviceId = 2, kind = UriBinding.KIND_WEB, value = "example2.com")
    )

    /** Keeps the call sites short; the real signature takes all three lists. */
    private fun write(
        entries: List<VaultEntry>,
        services: List<VaultService> = sampleServices(),
        bindings: List<UriBinding> = sampleBindings(),
        dek: javax.crypto.SecretKey = CryptoManager.newDataKey(),
        vaultCreatedAt: Long = 0L
    ) = BackupPackage.write(passphrase, dek, vaultCreatedAt, entries, services, bindings)

    private fun sampleEntries(count: Int = 3) = (1..count).map { i ->
        VaultEntry(
            id = i.toLong(),
            title = "Account $i",
            serviceId = (i % 2) + 1L,
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
        val bytes = write(entries, dek = dek, vaultCreatedAt = 42L)

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
        val bytes = write(sampleEntries(5))
        val header = BackupPackage.readHeader(bytes)

        assertEquals(BackupPackage.VERSION, header.version)
        assertEquals(5, header.entryCount)
        assertTrue(header.createdAt > 0)
        assertTrue(header.kdf.iterations >= 310_000)
    }

    @Test
    fun `carries no plaintext of the entries`() {
        val bytes = write(sampleEntries())
        val text = String(bytes, Charsets.UTF_8)
        // Titles and services live inside the sealed payload, not the header.
        assertTrue("Entry titles must not appear in the clear", !text.contains("Account 1"))
        assertTrue("Service names must not appear in the clear", !text.contains("Service 1"))
    }

    @Test
    fun `wrong passphrase returns null instead of partial data`() {
        val bytes = write(sampleEntries())
        assertNull(BackupPackage.open(bytes, "not-the-passphrase".toCharArray()))
    }

    @Test
    fun `a tampered payload does not open`() {
        val bytes = write(sampleEntries())
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
        val bytes = write(sampleEntries())
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
        val bytes = write(sampleEntries())
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
        val bytes = write(sampleEntries(3))
        val json = JSONObject(String(bytes, Charsets.UTF_8)).put("entryCount", 2)
        try {
            BackupPackage.open(json.toString().toByteArray(Charsets.UTF_8), passphrase)
            fail("Count mismatch should be rejected")
        } catch (e: BackupPackage.MalformedBackupException) {
            // expected
        }
    }

    // ── Services and bindings (format v2) ──────────────────────────────────

    @Test
    fun `round trips services and their uri bindings`() {
        val bytes = write(sampleEntries())
        val opened = BackupPackage.open(bytes, passphrase)!!

        assertEquals(sampleServices().map { it.name }, opened.services.map { it.name })
        assertEquals(sampleBindings().size, opened.bindings.size)
        assertEquals(
            sampleBindings().map { it.value to it.kind },
            opened.bindings.map { it.value to it.kind }
        )
        // The link between an entry and its service has to survive, or a restored
        // vault groups correctly and fills nothing.
        assertEquals(sampleEntries().map { it.serviceId }, opened.entries.map { it.serviceId })
    }

    @Test
    fun `drops a binding whose service did not survive`() {
        // A hand-edited or partially written file must not be able to insert a
        // binding that violates the foreign key, or restore fails as a whole.
        val bytes = write(sampleEntries(), services = sampleServices(1))
        val opened = BackupPackage.open(bytes, passphrase)!!

        assertEquals(1, opened.services.size)
        assertTrue(opened.bindings.all { it.serviceId == 1L })
    }

    @Test
    fun `a v1 backup still restores, with services rebuilt from entry names`() {
        // Simulate a file written before Phase 3: version 1, no services array,
        // entries carrying only the denormalised serviceName.
        val v2 = JSONObject(String(write(sampleEntries(4)), Charsets.UTF_8))
        val downgraded = JSONObject(v2.toString()).put("version", 1)

        val opened = BackupPackage.open(
            downgraded.toString().toByteArray(Charsets.UTF_8), passphrase
        )
        assertNotNull(opened)
        opened!!

        assertEquals(4, opened.entries.size)
        // sampleEntries alternates between two service names.
        assertEquals(2, opened.services.size)
        assertTrue(opened.bindings.isEmpty())
        // Every entry points at a service that is actually in the file.
        val ids = opened.services.map { it.id }.toSet()
        assertTrue(opened.entries.all { it.serviceId in ids })
    }

    @Test
    fun `a v1 backup files an ungrouped entry under its own title`() {
        val ungrouped = listOf(
            sampleEntries(1).first().copy(serviceId = 0L, serviceName = "", title = "Lone Account")
        )
        val v2 = JSONObject(String(write(ungrouped, services = emptyList(), bindings = emptyList()), Charsets.UTF_8))
        val opened = BackupPackage.open(
            JSONObject(v2.toString()).put("version", 1).toString().toByteArray(Charsets.UTF_8),
            passphrase
        )!!

        assertEquals(1, opened.services.size)
        assertEquals("Lone Account", opened.services.first().name)
        assertEquals(opened.services.first().id, opened.entries.first().serviceId)
    }

    @Test
    fun `a future version is still refused`() {
        val v2 = JSONObject(String(write(sampleEntries()), Charsets.UTF_8))
        val future = JSONObject(v2.toString()).put("version", 99)
        try {
            BackupPackage.readHeader(future.toString().toByteArray(Charsets.UTF_8))
            fail("A version this build cannot read must not be opened")
        } catch (e: BackupPackage.MalformedBackupException) {
            // expected
        }
    }
}
