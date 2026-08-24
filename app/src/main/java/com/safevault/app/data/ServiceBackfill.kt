package com.safevault.app.data

import android.content.Context
import com.safevault.app.autofill.UriNormalizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Second half of the 2 -> 3 migration: turns each entry's existing `website`
 * text into a real [UriBinding].
 *
 * The schema half runs in SQL inside the Room migration. This half does not,
 * because deriving a host from a URL is [UriNormalizer]'s job and a second
 * implementation written in SQLite string functions is how a credential ends up
 * offered to the wrong domain. Splitting the migration in two costs a boolean
 * flag; sharing the parser is worth more than that.
 *
 * It needs no vault key — `website` was never encrypted — so unlike
 * [com.safevault.app.security.LegacyVaultMigration] it can run at any point
 * after the database opens. It is idempotent regardless: binding inserts ignore
 * conflicts on the unique (service, kind, value) index, so a crash midway
 * re-runs harmlessly and the flag is only an optimisation.
 */
object ServiceBackfill {

    private const val PREFS = "vault_backfill"
    private const val KEY_DONE = "bindings_backfilled_v3"

    /**
     * @return the number of bindings created, or 0 if there was nothing to do.
     */
    suspend fun runIfNeeded(context: Context): Int = withContext(Dispatchers.IO) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getBoolean(KEY_DONE, false)) return@withContext 0

        val dao = VaultDatabase.get(context).vaultDao()
        var created = 0
        for (entry in dao.entriesWithWebsite()) {
            val serviceId = entry.serviceId
            if (serviceId <= 0L) continue
            val host = UriNormalizer.normalizeHost(entry.website)
            // A bare public suffix is not an identity. Binding one would offer
            // this credential to every site under it.
            if (host.isEmpty() || UriNormalizer.isPublicSuffixOnly(host)) continue
            val id = dao.insertBinding(
                UriBinding(
                    serviceId = serviceId,
                    kind = UriBinding.KIND_WEB,
                    value = host,
                    source = UriBinding.SOURCE_MIGRATION
                )
            )
            if (id > 0) created++
        }

        prefs.edit().putBoolean(KEY_DONE, true).apply()
        created
    }

    /**
     * Re-arms the back-fill. Restore replaces the whole database, including its
     * bindings, so the flag from the *previous* vault must not suppress a
     * back-fill the restored one may still need.
     */
    fun reset(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_DONE, false).apply()
    }
}
