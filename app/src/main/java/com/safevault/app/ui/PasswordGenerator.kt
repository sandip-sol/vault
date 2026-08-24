package com.safevault.app.ui

import java.security.SecureRandom
import kotlin.math.ln

/**
 * Generates passwords from a character set with the visually ambiguous glyphs
 * removed (0/O, 1/l/I), because these get read off a screen and retyped by hand
 * more often than the security literature likes to admit.
 *
 * Every enabled class is guaranteed present, then the result is shuffled —
 * sampling uniformly and hoping for coverage produces an all-lowercase password
 * often enough to matter at short lengths.
 */
object PasswordGenerator {

    const val DEFAULT_LENGTH = 20
    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 64

    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val DIGITS = "23456789"
    private const val SYMBOLS = "!@#\$%^&*()-_=+?"

    private val random = SecureRandom()

    data class Options(
        val length: Int = DEFAULT_LENGTH,
        val lowercase: Boolean = true,
        val uppercase: Boolean = true,
        val digits: Boolean = true,
        val symbols: Boolean = true
    ) {
        /** At least one class has to be on for there to be anything to sample. */
        val isUsable: Boolean get() = lowercase || uppercase || digits || symbols
    }

    fun generate(length: Int = DEFAULT_LENGTH): String =
        generate(Options(length = length))

    fun generate(options: Options): String {
        val classes = enabledClasses(options)
        require(classes.isNotEmpty()) { "At least one character class must be enabled" }

        val length = options.length.coerceIn(MIN_LENGTH, MAX_LENGTH)
        val all = classes.joinToString("")

        // Seed one character per class so short passwords cannot come out
        // single-class, then fill the rest from the combined pool.
        val chars = classes.take(length).map { pick(it) }.toMutableList()
        repeat(length - chars.size) { chars += pick(all) }

        shuffle(chars)
        return chars.joinToString("")
    }

    /**
     * Bits of entropy, as `length * log2(poolSize)`.
     *
     * Strictly this is an upper bound: guaranteeing one character per class
     * removes a little of the space. The overcount is under a bit at these
     * lengths, and rounding it away would understate the weaker settings that
     * actually deserve attention.
     */
    fun entropyBits(options: Options): Double {
        val pool = enabledClasses(options).sumOf { it.length }
        if (pool <= 1) return 0.0
        return options.length.coerceIn(MIN_LENGTH, MAX_LENGTH) * log2(pool.toDouble())
    }

    private fun enabledClasses(options: Options): List<String> = buildList {
        if (options.lowercase) add(LOWER)
        if (options.uppercase) add(UPPER)
        if (options.digits) add(DIGITS)
        if (options.symbols) add(SYMBOLS)
    }

    private fun pick(from: String) = from[random.nextInt(from.length)]

    /** Fisher-Yates over a CSPRNG; Collections.shuffle() would use Random. */
    private fun shuffle(chars: MutableList<Char>) {
        for (i in chars.indices.reversed()) {
            val j = random.nextInt(i + 1)
            chars[i] = chars[j].also { chars[j] = chars[i] }
        }
    }

    internal fun log2(value: Double) = ln(value) / ln(2.0)
}
