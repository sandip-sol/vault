package com.safevault.app.sync

import com.safevault.app.data.PasskeyCredential
import com.safevault.app.data.UriBinding
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultService
import com.safevault.app.security.CryptoManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SyncPackageTest {

    private val dek = CryptoManager.newDataKey()

    @Test
    fun `sync snapshot hides vault content from the server-visible envelope`() {
        val bytes = snapshot()
        val text = String(bytes, Charsets.UTF_8)

        assertTrue(!text.contains("Example Bank"))
        assertTrue(!text.contains("example.com"))
        assertTrue(!text.contains("encrypted-password"))
    }

    @Test
    fun `sync snapshot round trips every vault table`() {
        val opened = SyncPackage.open(snapshot(), dek)
        assertNotNull(opened)
        opened!!

        assertEquals(listOf("Example Bank"), opened.entries.map { it.title })
        assertEquals(listOf("Example"), opened.services.map { it.name })
        assertEquals(listOf("example.com"), opened.bindings.map { it.value })
        assertEquals(listOf("credential-id"), opened.passkeys.map { it.credentialId })
    }

    @Test
    fun `snapshot does not open with another vault key`() {
        assertNull(SyncPackage.open(snapshot(), CryptoManager.newDataKey()))
    }

    @Test
    fun `header is readable without the vault key`() {
        val header = SyncPackage.readHeader(snapshot())

        assertEquals(SyncPackage.VERSION, header.version)
        assertEquals("device-a", header.deviceId)
        assertEquals(7L, header.baseRevision)
        assertEquals(8L, header.revision)
    }

    private fun snapshot() = SyncPackage.write(
        dek = dek,
        deviceId = "device-a",
        baseRevision = 7L,
        revision = 8L,
        vaultCreatedAt = 42L,
        entries = listOf(
            VaultEntry(
                id = 1,
                title = "Example Bank",
                serviceId = 1,
                serviceName = "Example",
                website = "https://example.com",
                encryptedUsername = "encrypted-username",
                encryptedPassword = "encrypted-password"
            )
        ),
        services = listOf(VaultService(id = 1, name = "Example")),
        bindings = listOf(
            UriBinding(id = 1, serviceId = 1, kind = UriBinding.KIND_WEB, value = "example.com")
        ),
        passkeys = listOf(
            PasskeyCredential(
                id = 1,
                serviceId = 1,
                rpId = "example.com",
                credentialId = "credential-id",
                username = "person@example.com",
                encryptedUserHandle = "encrypted-handle",
                encryptedPrivateKey = "encrypted-private-key"
            )
        )
    )
}
