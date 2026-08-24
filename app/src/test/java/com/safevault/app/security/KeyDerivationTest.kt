package com.safevault.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KeyDerivationTest {

    @Test
    fun `same password and params give the same key`() {
        val params = KeyDerivation.newParams(iterations = 1_000)
        val a = KeyDerivation.deriveKek("passphrase".toCharArray(), params)
        val b = KeyDerivation.deriveKek("passphrase".toCharArray(), params)
        assertTrue(a.encoded.contentEquals(b.encoded))
    }

    @Test
    fun `a different salt gives a different key`() {
        val a = KeyDerivation.deriveKek(
            "passphrase".toCharArray(), KeyDerivation.newParams(iterations = 1_000)
        )
        val b = KeyDerivation.deriveKek(
            "passphrase".toCharArray(), KeyDerivation.newParams(iterations = 1_000)
        )
        assertFalse(
            "Fresh params must carry a fresh salt",
            a.encoded.contentEquals(b.encoded)
        )
    }

    @Test
    fun `derives 256 bits`() {
        val key = KeyDerivation.deriveKek(
            "x".toCharArray(), KeyDerivation.newParams(iterations = 1_000)
        )
        assertEquals(32, key.encoded.size)
    }

    @Test
    fun `backups use a higher work factor than unlock`() {
        assertTrue(KeyDerivation.BACKUP_ITERATIONS > KeyDerivation.VAULT_ITERATIONS)
    }
}
