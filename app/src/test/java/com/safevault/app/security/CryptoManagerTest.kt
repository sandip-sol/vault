package com.safevault.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import javax.crypto.AEADBadTagException

@RunWith(RobolectricTestRunner::class)
class CryptoManagerTest {

    private val aad = "entry/password/v2"

    @Test
    fun `round trips a value`() {
        val key = CryptoManager.newDataKey()
        val sealed = CryptoManager.encrypt("correct horse battery staple", key, aad)
        assertEquals("correct horse battery staple", CryptoManager.decrypt(sealed, key, aad))
    }

    @Test
    fun `produces a different ciphertext each time`() {
        val key = CryptoManager.newDataKey()
        val a = CryptoManager.encrypt("same", key, aad)
        val b = CryptoManager.encrypt("same", key, aad)
        assertNotEquals("IV reuse would leak equality of plaintexts", a, b)
    }

    @Test
    fun `rejects the wrong key`() {
        val sealed = CryptoManager.encrypt("secret", CryptoManager.newDataKey(), aad)
        assertFailsAuth { CryptoManager.decrypt(sealed, CryptoManager.newDataKey(), aad) }
    }

    @Test
    fun `rejects a ciphertext moved to another field`() {
        val key = CryptoManager.newDataKey()
        val sealed = CryptoManager.encrypt("hunter2", key, VaultAad.PASSWORD)
        // Lifting the password blob into the username column must not decrypt.
        assertFailsAuth { CryptoManager.decrypt(sealed, key, VaultAad.USERNAME) }
    }

    @Test
    fun `rejects a tampered ciphertext`() {
        val key = CryptoManager.newDataKey()
        val sealed = CryptoManager.encrypt("secret", key, aad)
        val flipped = sealed.dropLast(2) + if (sealed.last() == 'A') "B=" else "A="
        assertFailsAuth { CryptoManager.decrypt(flipped, key, aad) }
    }

    @Test
    fun `wraps and unwraps a data key`() {
        val dek = CryptoManager.newDataKey()
        val kek = CryptoManager.newDataKey()
        val wrapped = CryptoManager.wrapKey(dek, kek, "wrap")
        assertTrue(dek.encoded.contentEquals(CryptoManager.unwrapKey(wrapped, kek, "wrap").encoded))
    }

    @Test
    fun `unwrapping with the wrong kek fails rather than returning a bad key`() {
        val wrapped = CryptoManager.wrapKey(
            CryptoManager.newDataKey(), CryptoManager.newDataKey(), "wrap"
        )
        assertFailsAuth { CryptoManager.unwrapKey(wrapped, CryptoManager.newDataKey(), "wrap") }
    }

    @Test
    fun `distinguishes v2 payloads from legacy ones`() {
        val key = CryptoManager.newDataKey()
        assertTrue(CryptoManager.isCurrentSchema(CryptoManager.encrypt("x", key, aad)))
        assertTrue(!CryptoManager.isCurrentSchema("aGVsbG8gd29ybGQgcGFkZGluZw=="))
    }

    private fun assertFailsAuth(block: () -> Unit) {
        try {
            block()
            fail("Expected authentication to fail")
        } catch (e: AEADBadTagException) {
            // expected
        } catch (e: javax.crypto.BadPaddingException) {
            // some providers surface the same failure this way
        } catch (e: IllegalArgumentException) {
            // malformed input rejected before the cipher ran
        }
    }
}

/** Mirrors VaultRepository's constants without dragging Room into a unit test. */
private object VaultAad {
    const val USERNAME = "entry/username/v2"
    const val PASSWORD = "entry/password/v2"
}
