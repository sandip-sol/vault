package com.safevault.app.data

import android.content.Context
import com.safevault.app.autofill.UriNormalizer
import com.safevault.app.security.CryptoManager
import com.safevault.app.security.PasswordHealth
import kotlinx.coroutines.flow.Flow
import javax.crypto.SecretKey

/** A credential as the user edits it — plaintext, never persisted in this shape. */
data class CredentialDraft(
    val id: Long = 0,
    val title: String,
    val serviceName: String,
    val website: String,
    val username: String,
    val password: String,
    val notes: String,
    val favorite: Boolean = false
)

/**
 * A credential the autofill service may offer, paired with why it matched.
 *
 * [specificity] is how closely the binding named the request: an exact host or
 * package beats a parent-domain binding, so `login.example.com` sorts above a
 * bare `example.com` binding when both apply.
 */
data class CredentialMatch(
    val entry: VaultEntry,
    val specificity: Int
)

/** A decrypted credential for display. */
data class CredentialDetail(
    val entry: VaultEntry,
    val username: String,
    val password: String,
    val notes: String
)

/**
 * The single place where vault plaintext crosses into storage. Activities deal in
 * [CredentialDraft]/[CredentialDetail] and never call the cipher themselves, so
 * there is exactly one code path to audit for "did this get encrypted".
 */
class VaultRepository(context: Context) {

    private val dao = VaultDatabase.get(context).vaultDao()

    companion object {
        /**
         * Associated data binds each ciphertext to the column it belongs in.
         * Moving a password blob into the username column makes the tag fail.
         */
        const val AAD_USERNAME = "entry/username/v2"
        const val AAD_PASSWORD = "entry/password/v2"
        const val AAD_NOTES = "entry/notes/v2"

        /** Score for a binding that named the request exactly. */
        const val EXACT_SPECIFICITY = Int.MAX_VALUE
    }

    fun observeAll(): Flow<List<VaultEntry>> = dao.observeAll()

    suspend fun allServices(): List<VaultService> = dao.allServices()

    suspend fun serviceById(id: Long): VaultService? = dao.serviceById(id)

    suspend fun bindingsFor(serviceId: Long): List<UriBinding> = dao.bindingsFor(serviceId)

    suspend fun allBindings(): List<UriBinding> = dao.allBindings()

    suspend fun count(): Int = dao.count()

    suspend fun getAll(): List<VaultEntry> = dao.getAll()

    suspend fun load(id: Long, key: SecretKey): CredentialDetail? {
        val entry = dao.getById(id) ?: return null
        return CredentialDetail(
            entry = entry,
            username = decryptField(entry.encryptedUsername, key, AAD_USERNAME),
            password = decryptField(entry.encryptedPassword, key, AAD_PASSWORD),
            notes = when {
                entry.encryptedNotes.isNotEmpty() ->
                    decryptField(entry.encryptedNotes, key, AAD_NOTES)
                // A v1 row that has not been through the content migration yet.
                else -> entry.notes
            }
        )
    }

    suspend fun save(draft: CredentialDraft, key: SecretKey): Long {
        val now = System.currentTimeMillis()
        val existing = if (draft.id > 0) dao.getById(draft.id) else null
        val serviceName = draft.serviceName.trim().ifBlank { draft.title.trim() }
        val serviceId = resolveService(serviceName)
        val passwordChanged = existing == null ||
            decryptField(existing.encryptedPassword, key, AAD_PASSWORD) != draft.password

        val entry = VaultEntry(
            id = draft.id,
            title = draft.title,
            serviceId = serviceId,
            serviceName = serviceName,
            website = draft.website,
            encryptedUsername = CryptoManager.encrypt(draft.username, key, AAD_USERNAME),
            encryptedPassword = CryptoManager.encrypt(draft.password, key, AAD_PASSWORD),
            encryptedNotes = if (draft.notes.isEmpty()) ""
                else CryptoManager.encrypt(draft.notes, key, AAD_NOTES),
            notes = "",
            favorite = draft.favorite,
            reuseHash = PasswordHealth.reuseHash(draft.password, key),
            strengthScore = PasswordHealth.score(draft.password),
            passwordUpdatedAt = if (passwordChanged) now else (existing?.passwordUpdatedAt ?: now),
            createdAt = existing?.createdAt ?: now,
            updatedAt = now,
            lastUsedAt = existing?.lastUsedAt ?: 0L,
            payloadSchema = CryptoManager.SCHEMA_CURRENT
        )
        val id = dao.upsert(entry)

        // A URL the user typed is a statement about who this account belongs to,
        // so it becomes a binding. Autofill never reads the `website` column: it
        // matches bindings, and a binding is only ever a normalised host.
        bindWebsite(serviceId, draft.website, UriBinding.SOURCE_MANUAL)

        // Re-pointing the last entry off a service leaves it with no accounts and
        // no reason to exist; its bindings go with it.
        if (existing != null && existing.serviceId != serviceId) dao.deleteOrphanServices()

        return id
    }

    // ── Services and bindings ──────────────────────────────────────────────

    /**
     * The id of the service called [name], creating it if it is new.
     *
     * The insert ignores conflicts and is followed by a read rather than trusting
     * the returned row id: `services.name` is NOCASE-unique, so saving an account
     * under "GitHub" when "github" already exists must join the existing service,
     * not fail and not fork a second one.
     */
    suspend fun resolveService(name: String): Long {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return 0L
        dao.serviceByName(trimmed)?.let { return it.id }
        val now = System.currentTimeMillis()
        val inserted = dao.insertService(VaultService(name = trimmed, createdAt = now, updatedAt = now))
        return if (inserted > 0) inserted else dao.serviceByName(trimmed)?.id ?: 0L
    }

    /** Records a web binding for [rawUrl] if it normalises to a usable host. */
    suspend fun bindWebsite(serviceId: Long, rawUrl: String, source: Int): Boolean {
        if (serviceId <= 0L) return false
        val host = UriNormalizer.normalizeHost(rawUrl)
        if (host.isEmpty() || UriNormalizer.isPublicSuffixOnly(host)) return false
        return addBinding(serviceId, UriBinding.KIND_WEB, host, source)
    }

    /** Records an Android package binding if [rawPackage] is a valid application id. */
    suspend fun bindPackage(serviceId: Long, rawPackage: String, source: Int): Boolean {
        if (serviceId <= 0L) return false
        val pkg = UriNormalizer.normalizePackage(rawPackage)
        if (pkg.isEmpty()) return false
        return addBinding(serviceId, UriBinding.KIND_ANDROID_APP, pkg, source)
    }

    private suspend fun addBinding(serviceId: Long, kind: Int, value: String, source: Int): Boolean {
        // IGNORE on the unique (serviceId, kind, value) index: re-saving the same
        // login should not grow the table or produce a duplicate dataset.
        val id = dao.insertBinding(
            UriBinding(serviceId = serviceId, kind = kind, value = value, source = source)
        )
        return id > 0
    }

    suspend fun removeBinding(id: Long) = dao.deleteBinding(id)

    /**
     * The account on [serviceId] whose username is [username], if there is one.
     *
     * Usernames are ciphertext, so this decrypts each candidate rather than
     * querying — which is why it is scoped to a single service. It exists so an
     * autofill save can tell "the user changed their password" from "the user has
     * a second account here", and update rather than silently accumulate
     * duplicates of the same login.
     */
    suspend fun findAccount(serviceId: Long, username: String, key: SecretKey): VaultEntry? {
        if (serviceId <= 0L) return null
        return dao.entriesForServices(listOf(serviceId)).firstOrNull { entry ->
            val stored = try {
                decryptField(entry.encryptedUsername, key, AAD_USERNAME)
            } catch (e: Exception) {
                return@firstOrNull false
            }
            stored.equals(username, ignoreCase = true)
        }
    }

    /** The service bound to this host or package, if the vault already knows it. */
    suspend fun serviceForTarget(webHost: String, packageName: String): VaultService? {
        val bindings = if (webHost.isNotEmpty()) {
            val candidates = UriNormalizer.expandHostCandidates(webHost)
            if (candidates.isEmpty()) emptyList()
            else dao.findBindings(UriBinding.KIND_WEB, candidates)
                .filter { UriNormalizer.hostMatches(it.value, webHost) }
        } else {
            val pkg = UriNormalizer.normalizePackage(packageName)
            if (pkg.isEmpty()) emptyList() else dao.findBindings(UriBinding.KIND_ANDROID_APP, listOf(pkg))
        }
        // Most specific binding wins, same rule the fill path uses.
        val best = bindings.maxByOrNull { it.value.length } ?: return null
        return dao.serviceById(best.serviceId)
    }

    // ── Autofill lookup ────────────────────────────────────────────────────

    /**
     * Credentials bound to [requestHost], most specific first.
     *
     * The host is expanded to the exact set a binding may hold (see
     * [UriNormalizer.expandHostCandidates]) so the lookup is an indexed equality
     * search. A binding naming the host itself outranks one naming a parent
     * domain, because the user was more precise about it.
     */
    suspend fun matchesForHost(requestHost: String): List<CredentialMatch> {
        val candidates = UriNormalizer.expandHostCandidates(requestHost)
        if (candidates.isEmpty()) return emptyList()
        val bindings = dao.findBindings(UriBinding.KIND_WEB, candidates)
            .filter { UriNormalizer.hostMatches(it.value, requestHost) }
        return collect(bindings) { binding ->
            // Longer binding = fewer sites it covers = a closer statement of identity.
            binding.value.length
        }
    }

    /** Credentials bound to the Android application id [requestPackage]. */
    suspend fun matchesForPackage(requestPackage: String): List<CredentialMatch> {
        val pkg = UriNormalizer.normalizePackage(requestPackage)
        if (pkg.isEmpty()) return emptyList()
        val bindings = dao.findBindings(UriBinding.KIND_ANDROID_APP, listOf(pkg))
        // A package binding is exact or it is not a match at all, so every hit
        // scores the same and ties fall through to the recency ordering below.
        return collect(bindings) { EXACT_SPECIFICITY }
    }

    private suspend fun collect(
        bindings: List<UriBinding>,
        specificity: (UriBinding) -> Int
    ): List<CredentialMatch> {
        if (bindings.isEmpty()) return emptyList()
        val best = bindings.groupBy { it.serviceId }
            .mapValues { (_, group) -> group.maxOf(specificity) }
        return dao.entriesForServices(best.keys.toList())
            .map { CredentialMatch(it, best[it.serviceId] ?: 0) }
            .sortedWith(
                compareByDescending<CredentialMatch> { it.specificity }
                    .thenByDescending { it.entry.lastUsedAt }
                    .thenBy { it.entry.title.lowercase() }
            )
    }

    suspend fun delete(entry: VaultEntry) {
        dao.delete(entry)
        // The service outlives its last account only as a set of bindings that
        // can now match nothing, so it goes too.
        dao.deleteOrphanServices()
    }

    suspend fun setFavorite(id: Long, favorite: Boolean) = dao.setFavorite(id, favorite)

    suspend fun markUsed(id: Long) = dao.markUsed(id, System.currentTimeMillis())

    /** Restore: the whole vault, services and bindings included. */
    suspend fun replaceVault(
        entries: List<VaultEntry>,
        services: List<VaultService>,
        bindings: List<UriBinding>
    ) = dao.replaceVault(entries, services, bindings)

    /**
     * Reads a field written under either payload schema. v1 rows are readable
     * until the content migration re-seals them; after that only v2 is produced.
     */
    private fun decryptField(payload: String, key: SecretKey, aad: String): String {
        if (payload.isEmpty()) return ""
        return if (CryptoManager.isCurrentSchema(payload)) {
            CryptoManager.decrypt(payload, key, aad)
        } else {
            CryptoManager.openLegacy(payload, key)
        }
    }
}
