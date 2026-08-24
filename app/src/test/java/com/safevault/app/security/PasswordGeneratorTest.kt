package com.safevault.app.security

import com.safevault.app.ui.PasswordGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordGeneratorTest {

    @Test
    fun `honours the requested length`() {
        listOf(8, 16, 20, 32).forEach {
            assertEquals(it, PasswordGenerator.generate(it).length)
        }
    }

    @Test
    fun `always includes every character class`() {
        repeat(200) {
            val password = PasswordGenerator.generate(12)
            assertTrue("no lowercase in $password", password.any { c -> c.isLowerCase() })
            assertTrue("no uppercase in $password", password.any { c -> c.isUpperCase() })
            assertTrue("no digit in $password", password.any { c -> c.isDigit() })
            assertTrue("no symbol in $password", password.any { c -> !c.isLetterOrDigit() })
        }
    }

    @Test
    fun `omits visually ambiguous characters`() {
        val ambiguous = setOf('0', 'O', '1', 'l', 'I')
        repeat(200) {
            PasswordGenerator.generate(24).forEach { c ->
                assertTrue("ambiguous '$c' should not appear", c !in ambiguous)
            }
        }
    }

    @Test
    fun `respects disabled character classes`() {
        val noSymbols = PasswordGenerator.Options(length = 24, symbols = false)
        repeat(100) {
            PasswordGenerator.generate(noSymbols).forEach { c ->
                assertTrue("symbol '$c' leaked in", c.isLetterOrDigit())
            }
        }

        val digitsOnly = PasswordGenerator.Options(
            length = 16, lowercase = false, uppercase = false, symbols = false
        )
        repeat(100) {
            assertTrue(PasswordGenerator.generate(digitsOnly).all { it.isDigit() })
        }
    }

    @Test
    fun `clamps a length outside the supported range`() {
        assertEquals(PasswordGenerator.MIN_LENGTH, PasswordGenerator.generate(2).length)
        assertEquals(PasswordGenerator.MAX_LENGTH, PasswordGenerator.generate(500).length)
    }

    @Test
    fun `entropy tracks length and pool size`() {
        val full = PasswordGenerator.Options(length = 20)
        val narrow = PasswordGenerator.Options(
            length = 20, uppercase = false, digits = false, symbols = false
        )
        assertTrue(PasswordGenerator.entropyBits(full) > PasswordGenerator.entropyBits(narrow))

        val longer = PasswordGenerator.Options(length = 40)
        assertEquals(
            2 * PasswordGenerator.entropyBits(full),
            PasswordGenerator.entropyBits(longer),
            0.001
        )
    }

    @Test
    fun `an options set with every class off is rejected`() {
        val none = PasswordGenerator.Options(
            lowercase = false, uppercase = false, digits = false, symbols = false
        )
        assertTrue(!none.isUsable)
        try {
            PasswordGenerator.generate(none)
            org.junit.Assert.fail("Expected rejection")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `does not repeat itself`() {
        val generated = List(100) { PasswordGenerator.generate(16) }
        assertEquals(generated.size, generated.distinct().size)
    }
}
