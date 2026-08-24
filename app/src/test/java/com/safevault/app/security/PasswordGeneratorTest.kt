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
    fun `does not repeat itself`() {
        val generated = List(100) { PasswordGenerator.generate(16) }
        assertEquals(generated.size, generated.distinct().size)
    }
}
