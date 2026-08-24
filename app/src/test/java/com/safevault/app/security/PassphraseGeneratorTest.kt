package com.safevault.app.security

import com.safevault.app.ui.PassphraseGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PassphraseGeneratorTest {

    /** The shipped list, read from res/raw so the tests check what users get. */
    private val words: List<String> =
        File("src/main/res/raw/wordlist.txt").readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }

    private val generator = PassphraseGenerator(words)

    // ── The wordlist itself ────────────────────────────────────────────────

    @Test
    fun `wordlist is exactly 1024 words so entropy is exactly 10 bits each`() {
        assertEquals(1024, words.size)
    }

    @Test
    fun `wordlist has no duplicates`() {
        // A duplicate would silently reduce entropy below the claimed figure.
        assertEquals(words.size, words.toSet().size)
    }

    @Test
    fun `wordlist is lowercase ascii letters only`() {
        words.forEach { word ->
            assertTrue("'$word' is not plain lowercase ascii", word.all { it in 'a'..'z' })
        }
    }

    @Test
    fun `wordlist words are short enough to retype`() {
        words.forEach { assertTrue("'$it' is too long", it.length in 3..7) }
    }

    // ── Generation ─────────────────────────────────────────────────────────

    @Test
    fun `produces the requested number of words`() {
        (PassphraseGenerator.MIN_WORDS..PassphraseGenerator.MAX_WORDS).forEach { count ->
            val phrase = generator.generate(PassphraseGenerator.Options(words = count))
            assertEquals(count, phrase.split("-").size)
        }
    }

    @Test
    fun `honours the separator`() {
        val phrase = generator.generate(PassphraseGenerator.Options(words = 4, separator = "."))
        assertEquals(4, phrase.split(".").size)
        assertTrue(!phrase.contains("-"))
    }

    @Test
    fun `capitalises each word when asked`() {
        val phrase = generator.generate(
            PassphraseGenerator.Options(words = 4, capitalize = true)
        )
        phrase.split("-").forEach { assertTrue("'$it' not capitalised", it.first().isUpperCase()) }
    }

    @Test
    fun `appends a two-digit number when asked`() {
        repeat(50) {
            val phrase = generator.generate(
                PassphraseGenerator.Options(words = 4, appendNumber = true)
            )
            val parts = phrase.split("-")
            assertEquals(5, parts.size)
            assertEquals(2, parts.last().length)
            assertTrue(parts.last().all { it.isDigit() })
        }
    }

    @Test
    fun `clamps a word count outside the supported range`() {
        assertEquals(
            PassphraseGenerator.MIN_WORDS,
            generator.generate(PassphraseGenerator.Options(words = 1)).split("-").size
        )
        assertEquals(
            PassphraseGenerator.MAX_WORDS,
            generator.generate(PassphraseGenerator.Options(words = 99)).split("-").size
        )
    }

    @Test
    fun `only ever emits words from the list`() {
        val pool = words.toSet()
        repeat(100) {
            generator.generate(PassphraseGenerator.Options(words = 6))
                .split("-")
                .forEach { assertTrue("'$it' is not in the wordlist", it in pool) }
        }
    }

    @Test
    fun `does not repeat itself`() {
        val phrases = List(200) { generator.generate(PassphraseGenerator.Options(words = 5)) }
        assertEquals(phrases.size, phrases.distinct().size)
    }

    // ── Entropy ────────────────────────────────────────────────────────────

    @Test
    fun `entropy is ten bits per word`() {
        assertEquals(50.0, generator.entropyBits(PassphraseGenerator.Options(words = 5)), 0.001)
        assertEquals(60.0, generator.entropyBits(PassphraseGenerator.Options(words = 6)), 0.001)
    }

    @Test
    fun `an appended number counts toward entropy rather than being free strength`() {
        val without = generator.entropyBits(PassphraseGenerator.Options(words = 5))
        val with = generator.entropyBits(
            PassphraseGenerator.Options(words = 5, appendNumber = true)
        )
        assertTrue(with > without)
        assertEquals(6.49, with - without, 0.01)
    }
}
