package com.safevault.app.ui

import java.security.SecureRandom

/**
 * Generates passwords from a character set with the visually ambiguous glyphs
 * removed (0/O, 1/l/I), because these get read off a screen and retyped by hand
 * more often than the security literature likes to admit.
 *
 * Every class is guaranteed present, then the result is shuffled — sampling
 * uniformly and hoping for coverage produces an all-lowercase password often
 * enough to matter at short lengths.
 */
object PasswordGenerator {

    const val DEFAULT_LENGTH = 20

    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val DIGITS = "23456789"
    private const val SYMBOLS = "!@#\$%^&*()-_=+?"

    private val random = SecureRandom()

    fun generate(length: Int = DEFAULT_LENGTH): String {
        val classes = listOf(LOWER, UPPER, DIGITS, SYMBOLS)
        val all = classes.joinToString("")

        val chars = MutableList(classes.size) { i -> pick(classes[i]) }
        repeat(length - classes.size) { chars += pick(all) }

        // Fisher-Yates with a CSPRNG; Collections.shuffle() would use Random.
        for (i in chars.indices.reversed()) {
            val j = random.nextInt(i + 1)
            chars[i] = chars[j].also { chars[j] = chars[i] }
        }
        return chars.joinToString("")
    }

    private fun pick(from: String) = from[random.nextInt(from.length)]
}
