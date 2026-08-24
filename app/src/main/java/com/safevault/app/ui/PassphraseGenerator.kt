package com.safevault.app.ui

import android.content.Context
import com.safevault.app.R
import java.security.SecureRandom
import java.util.Locale

/**
 * Diceware-style passphrases: words drawn uniformly, with replacement, from a
 * fixed list.
 *
 * The list is exactly 1024 words, which makes the entropy arithmetic exact and
 * checkable — 10 bits per word, so six words is 60 bits and nobody has to trust
 * a rounded claim. Words are 3–7 letters and free of the glyph pairs that make
 * a passphrase hard to retype.
 *
 * Entropy comes from the *count of possibilities*, not from how strange the
 * result looks, so the words being ordinary and memorable costs nothing. It
 * does mean the list must be public and fixed: picking "unusual" words by hand
 * is what makes a passphrase weak.
 */
class PassphraseGenerator(private val words: List<String>) {

    init {
        require(words.size >= 2) { "Wordlist is too small to generate from" }
    }

    companion object {
        const val DEFAULT_WORD_COUNT = 5
        const val MIN_WORDS = 3
        const val MAX_WORDS = 10

        /** Separators offered in the UI; the first is the default. */
        val SEPARATORS = listOf("-", ".", "_", " ")

        fun load(context: Context): PassphraseGenerator {
            val words = context.resources.openRawResource(R.raw.wordlist)
                .bufferedReader()
                .useLines { lines -> lines.map { it.trim() }.filter { it.isNotEmpty() }.toList() }
            return PassphraseGenerator(words)
        }
    }

    private val random = SecureRandom()

    val wordCount: Int get() = words.size

    data class Options(
        val words: Int = DEFAULT_WORD_COUNT,
        val separator: String = SEPARATORS.first(),
        val capitalize: Boolean = false,
        val appendNumber: Boolean = false
    )

    fun generate(options: Options = Options()): String {
        val count = options.words.coerceIn(MIN_WORDS, MAX_WORDS)

        val picked = (0 until count).map {
            val word = words[random.nextInt(words.size)]
            if (options.capitalize) word.replaceFirstChar { c -> c.titlecase(Locale.ROOT) } else word
        }

        val phrase = picked.joinToString(options.separator)
        // Appended for sites that demand a digit. It adds ~3.3 bits, which is
        // why entropyBits counts it rather than treating it as free strength.
        return if (options.appendNumber) phrase + options.separator + (10 + random.nextInt(90)) else phrase
    }

    /** Bits of entropy: `words * log2(listSize)`, plus the optional number. */
    fun entropyBits(options: Options): Double {
        val count = options.words.coerceIn(MIN_WORDS, MAX_WORDS)
        val base = count * PasswordGenerator.log2(words.size.toDouble())
        return if (options.appendNumber) base + PasswordGenerator.log2(90.0) else base
    }
}
