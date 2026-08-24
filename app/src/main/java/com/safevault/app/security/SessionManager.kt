package com.safevault.app.security

import javax.crypto.SecretKey

/**
 * Holds the decrypted vault DEK for the life of an unlocked session, and nothing
 * else. Locking clears the reference and zeroes the key material that we own.
 *
 * Auto-lock is evaluated against *process* background time (see SafeVaultApp),
 * not per-activity, so moving between the vault list and the editor no longer
 * counts as leaving the app — and genuinely leaving the app locks every screen
 * at once rather than only whichever one happened to be resumed.
 */
object SessionManager {

    @Volatile
    private var sessionKey: SecretKey? = null

    @Volatile
    private var backgroundedAt: Long = 0L

    val isUnlocked: Boolean get() = sessionKey != null

    val key: SecretKey? get() = sessionKey

    /** Throws if called while locked — callers on a secret path should not guess. */
    fun requireKey(): SecretKey = sessionKey ?: error("Vault is locked")

    fun unlock(dek: SecretKey) {
        sessionKey = dek
        backgroundedAt = 0L
    }

    fun lock() {
        sessionKey = null
        backgroundedAt = 0L
    }

    fun onEnterBackground() {
        backgroundedAt = System.currentTimeMillis()
    }

    /**
     * @return true if the session was locked because the timeout elapsed.
     */
    fun onEnterForeground(autoLockMs: Long): Boolean {
        val since = backgroundedAt
        backgroundedAt = 0L
        if (!isUnlocked) return false
        if (since > 0L && System.currentTimeMillis() - since >= autoLockMs) {
            lock()
            return true
        }
        return false
    }

    /**
     * Applies the auto-lock timeout without waiting for a foreground transition.
     *
     * Every other caller learns the session has expired because an activity came
     * back to the front. Autofill has no such moment: the vault is backgrounded,
     * the user is in Chrome, and the service is asked for datasets in a process
     * that may have had no visible activity for an hour. Reading [isUnlocked]
     * there would report a session that only *looks* alive because nothing has
     * resumed to retire it — and would hand out secrets on the strength of it.
     *
     * Unlike [onEnterForeground] this does not clear the background timestamp: it
     * is a check, not a lifecycle event, and the session is still in the
     * background after it runs.
     *
     * @return true if the vault is unlocked *and* still within its timeout.
     */
    fun isUnlockedWithin(autoLockMs: Long): Boolean {
        if (!isUnlocked) return false
        val since = backgroundedAt
        if (since > 0L && System.currentTimeMillis() - since >= autoLockMs) {
            lock()
            return false
        }
        return true
    }
}
