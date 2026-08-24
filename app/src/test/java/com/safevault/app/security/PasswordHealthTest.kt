package com.safevault.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PasswordHealthTest {

    @Test
    fun `scores an empty password as zero`() {
        assertEquals(0, PasswordHealth.score(""))
    }

    @Test
    fun `flags common passwords as weak whatever their shape`() {
        listOf("password", "123456", "qwerty", "letmein").forEach {
            assertEquals("'$it' should be weak", PasswordHealth.SCORE_WEAK, PasswordHealth.score(it))
        }
    }

    @Test
    fun `flags sequences and repeats as weak`() {
        assertEquals(PasswordHealth.SCORE_WEAK, PasswordHealth.score("abcdefgh"))
        assertEquals(PasswordHealth.SCORE_WEAK, PasswordHealth.score("aaaaaaaaaa"))
    }

    @Test
    fun `rates a generated password highly`() {
        val generated = com.safevault.app.ui.PasswordGenerator.generate()
        assertTrue(
            "Generator output should not be rated weak",
            PasswordHealth.score(generated) > PasswordHealth.SCORE_FAIR
        )
    }

    @Test
    fun `credits length as well as character variety`() {
        val longSimple = "correcthorsebatterystaple"
        val shortMixed = "aB3!aB3!"
        assertTrue(PasswordHealth.score(longSimple) > PasswordHealth.SCORE_WEAK)
        assertTrue(PasswordHealth.score(shortMixed) > PasswordHealth.SCORE_WEAK)
    }

    @Test
    fun `reuse hash matches for identical passwords under one vault key`() {
        val dek = CryptoManager.newDataKey()
        assertEquals(
            PasswordHealth.reuseHash("shared-secret", dek),
            PasswordHealth.reuseHash("shared-secret", dek)
        )
    }

    @Test
    fun `reuse hash differs for different passwords`() {
        val dek = CryptoManager.newDataKey()
        assertNotEquals(
            PasswordHealth.reuseHash("one", dek),
            PasswordHealth.reuseHash("two", dek)
        )
    }

    @Test
    fun `reuse hash is keyed to the vault so it cannot be compared across vaults`() {
        assertNotEquals(
            PasswordHealth.reuseHash("same", CryptoManager.newDataKey()),
            PasswordHealth.reuseHash("same", CryptoManager.newDataKey())
        )
    }

    @Test
    fun `empty password has no reuse hash`() {
        assertEquals("", PasswordHealth.reuseHash("", CryptoManager.newDataKey()))
    }
}
