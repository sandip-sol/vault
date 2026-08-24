package com.safevault.app.autofill

import java.util.UUID

/**
 * A credential the user just typed into someone else's form, waiting to be
 * written to the vault.
 *
 * [password] is plaintext, which is why this is not `Parcelable` and never
 * travels in an `Intent`. The save flow needs a `PendingIntent` so the platform
 * can start the confirmation screen, and a `PendingIntent`'s extras are held by
 * the system on the app's behalf — a place a vault password has no business
 * being. Instead the candidate stays in this process and the intent carries only
 * the [token] that finds it again, via [PendingSaves].
 *
 * If the process dies before the user confirms, the candidate goes with it and
 * the save is simply lost. That is the correct failure: a dropped save costs one
 * re-entry, and the alternative is durable plaintext.
 */
data class SaveCandidate(
    val token: String = UUID.randomUUID().toString(),
    val username: String,
    val password: String,
    /** Normalised web host, or "" for a native app form. */
    val webHost: String,
    /** Application id of the app the form belonged to. */
    val packageName: String,
    /** The form looked like registration or a password change, not a sign-in. */
    val isNewCredential: Boolean
) {
    /** What the user will recognise this as: the site, or the app's package. */
    val displayTarget: String get() = webHost.ifBlank { packageName }

    companion object {
        /**
         * Reads the submitted values out of a parsed form.
         *
         * @return null when there is no password to save. A username on its own
         *   is not a credential, and saving one would create an entry that can
         *   never fill anything.
         */
        fun from(parsed: ParsedStructure): SaveCandidate? {
            val password = passwordValueForSave(parsed.passwordFields.map { it.type to it.value })
                ?: return null

            val username = parsed.usernameFields
                .mapNotNull { it.value }
                .firstOrNull { it.isNotBlank() }
                .orEmpty()

            return SaveCandidate(
                username = username,
                password = password,
                webHost = parsed.webHost,
                packageName = parsed.packageName,
                isNewCredential = parsed.passwordFields.any { it.type == FieldType.NEW_PASSWORD }
            )
        }

        internal fun passwordValueForSave(fields: List<Pair<FieldType, String?>>): String? {
            val submitted = fields.mapNotNull { (type, value) ->
                value?.takeIf { it.isNotBlank() }?.let { type to it }
            }
            return submitted.firstOrNull { it.first == FieldType.NEW_PASSWORD }?.second
                ?: submitted.firstOrNull { it.first == FieldType.PASSWORD }?.second
        }
    }
}

/**
 * In-memory hand-off between the autofill service and the save screen.
 *
 * Both live in the same process, so a plaintext credential can be passed by
 * reference rather than serialised through the platform. Entries are removed
 * when taken and expire on their own, so a save the user abandons does not leave
 * a password sitting in memory until the process happens to die.
 */
object PendingSaves {

    /** Long enough for a user to read a prompt and unlock; short enough to forget. */
    private const val TTL_MS = 5 * 60 * 1000L

    private val pending = HashMap<String, Pair<SaveCandidate, Long>>()

    @Synchronized
    fun offer(candidate: SaveCandidate): String {
        sweep()
        pending[candidate.token] = candidate to System.currentTimeMillis()
        return candidate.token
    }

    /** Returns the candidate once; a second call for the same token gets null. */
    @Synchronized
    fun take(token: String?): SaveCandidate? {
        sweep()
        if (token == null) return null
        return pending.remove(token)?.first
    }

    @Synchronized
    fun clear() = pending.clear()

    private fun sweep() {
        val cutoff = System.currentTimeMillis() - TTL_MS
        pending.entries.removeAll { it.value.second < cutoff }
    }
}
