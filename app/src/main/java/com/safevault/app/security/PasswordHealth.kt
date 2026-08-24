package com.safevault.app.security

import android.util.Base64
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Local-only password health (roadmap §4, Phase 2 backlog). Everything here is
 * computed on-device from the vault's own contents — no hash prefix is sent
 * anywhere, and there is no network path to send it down. Remote breach lookup
 * stays a later, opt-in feature.
 */
object PasswordHealth {

    /** 0 = empty, 1 = weak, 2 = fair, 3 = strong, 4 = excellent. */
    const val SCORE_WEAK = 1
    const val SCORE_FAIR = 2
    const val SCORE_STRONG = 3

    private const val REUSE_INFO = "safevault/reuse-hmac/v1"

    private val COMMON = setOf(
        "password", "123456", "12345678", "qwerty", "abc123", "letmein",
        "monkey", "111111", "iloveyou", "admin", "welcome", "login",
        "passw0rd", "master", "dragon", "sunshine", "princess", "football"
    )

    fun score(password: String): Int {
        if (password.isEmpty()) return 0

        val lower = password.lowercase()
        if (lower in COMMON) return SCORE_WEAK
        if (COMMON.any { lower.startsWith(it) && password.length <= it.length + 3 }) return SCORE_WEAK

        var classes = 0
        if (password.any { it.isLowerCase() }) classes++
        if (password.any { it.isUpperCase() }) classes++
        if (password.any { it.isDigit() }) classes++
        if (password.any { !it.isLetterOrDigit() }) classes++

        // Long-but-simple (a passphrase) and short-but-mixed both earn credit.
        var points = when {
            password.length >= 20 -> 3
            password.length >= 16 -> 2
            password.length >= 12 -> 1
            password.length >= 8 -> 0
            else -> -1
        }
        points += when (classes) {
            4 -> 2
            3 -> 1
            2 -> 0
            else -> -1
        }
        if (isSingleRepeatedChar(password) || isSequential(lower)) points -= 2

        return points.coerceIn(1, 4)
    }

    fun label(score: Int): String = when (score) {
        0 -> "Empty"
        SCORE_WEAK -> "Weak"
        SCORE_FAIR -> "Fair"
        SCORE_STRONG -> "Strong"
        else -> "Excellent"
    }

    /**
     * A keyed digest used only to spot the same password stored twice.
     *
     * Keyed with a subkey of the vault DEK, so the stored value is meaningless to
     * anyone who lifts the database without the key — an unkeyed hash of a
     * password would be trivially brute-forceable offline.
     */
    fun reuseHash(password: String, dek: SecretKey): String {
        if (password.isEmpty()) return ""
        val subKey = hmac(dek.encoded, REUSE_INFO.toByteArray(Charsets.UTF_8))
        val digest = hmac(subKey, password.toByteArray(Charsets.UTF_8))
        // 128 bits is ample for equality checks and halves what we persist.
        return Base64.encodeToString(digest.copyOf(16), Base64.NO_WRAP)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(key, "HmacSHA256"))
        }.doFinal(data)

    private fun isSingleRepeatedChar(s: String) = s.length > 1 && s.all { it == s[0] }

    private fun isSequential(s: String): Boolean {
        if (s.length < 4) return false
        val ascending = s.zipWithNext().all { (a, b) -> b - a == 1 }
        val descending = s.zipWithNext().all { (a, b) -> a - b == 1 }
        return ascending || descending
    }
}
