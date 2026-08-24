package com.safevault.app.autofill

import android.app.PendingIntent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.RemoteViews
import com.safevault.app.R
import com.safevault.app.data.CredentialMatch
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Fills SafeVault credentials into other apps and browsers.
 *
 * This is the first thing in SafeVault that hands a secret to another process,
 * so the rules it works under are worth stating rather than leaving implied:
 *
 * **A locked vault reveals nothing, including whether it has a match.** When the
 * session is locked the response is a single authentication entry, built without
 * ever querying the database. Querying first and only offering the unlock entry
 * when something matched would turn the autofill dropdown into an oracle: point
 * a form at a domain, watch whether SafeVault offers to unlock, and learn what is
 * in a vault you cannot open. The dataset is therefore constructed *after*
 * authentication, in [AutofillAuthActivity], and not before.
 *
 * **Secrets are never in a presentation.** The dropdown row and the inline chip
 * are rendered by the requesting app and by the keyboard respectively. They show
 * a title and a username. The password exists only in the [Dataset] value, which
 * the platform hands to the target app if — and only if — the user picks the row.
 *
 * **The vault does not fill itself.** A request from our own package is refused:
 * a credential in SafeVault's own UI already came from the vault, and honouring
 * such a request would make the service a way to read the vault from inside a
 * screenshot-blocked screen.
 *
 * **A background session still expires.** [SessionManager.isUnlockedWithin] is
 * used rather than `isUnlocked`, because a fill request arrives with the app in
 * the background where no lifecycle callback has run to retire an expired
 * session. See the note on that function.
 */
class SafeVaultAutofillService : AutofillService() {

    private val job = Job()
    private val scope = CoroutineScope(SupervisorJob(job))

    private val repository by lazy { VaultRepository(this) }
    private val prefs by lazy { VaultPrefs(this) }

    companion object {
        /** More rows than a dropdown can usefully show. */
        private const val MAX_DATASETS = 8
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    // ── Fill ───────────────────────────────────────────────────────────────

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }

        val parsed = StructureParser.parse(structure)

        // Not a login form, or our own UI. Either way there is nothing to offer.
        if (!parsed.fillable || parsed.packageName == packageName) {
            callback.onSuccess(null)
            return
        }

        val inlineRequest = inlineRequestOf(request)

        if (!SessionManager.isUnlockedWithin(prefs.autoLockMs)) {
            // Deliberately before any database access — see the class comment.
            callback.onSuccess(lockedResponse(parsed, inlineRequest))
            return
        }

        val work = scope.launch {
            val matches = lookup(parsed)
            if (cancellationSignal.isCanceled) return@launch

            // The session can expire between the check above and this line; the
            // lookup runs off the main thread and the user may have walked away.
            // Re-checking here is what stops a decrypted dataset being built for
            // a vault that locked while we were reading it.
            if (!SessionManager.isUnlockedWithin(prefs.autoLockMs)) {
                callback.onSuccess(lockedResponse(parsed, inlineRequest))
                return@launch
            }

            callback.onSuccess(unlockedResponse(parsed, matches, inlineRequest))
        }
        cancellationSignal.setOnCancelListener { work.cancel() }
    }

    private suspend fun lookup(parsed: ParsedStructure): List<CredentialMatch> =
        if (parsed.isWebRequest) {
            repository.matchesForHost(parsed.webHost)
        } else {
            repository.matchesForPackage(parsed.packageName)
        }

    /**
     * The response for a locked vault: one entry that unlocks, and a `SaveInfo`
     * so a credential typed by hand can still be offered for saving afterwards.
     *
     * The same response is returned whether or not the vault holds a match,
     * because it is built without looking.
     */
    private fun lockedResponse(
        parsed: ParsedStructure,
        inlineRequest: InlineSuggestionsRequest?
    ): FillResponse {
        val ids = parsed.autofillIds()
        val presentation = presentation(
            getString(R.string.autofill_unlock_title),
            getString(R.string.autofill_unlock_subtitle)
        )
        // The activity is given the AssistStructure back by the platform, so
        // nothing about this form has to be parcelled into the sender.
        val sender = AutofillAuthActivity.intentSender(this, parsed.hashCode())

        val builder = FillResponse.Builder()
        val inline = inlineRequest?.let {
            InlinePresentations.build(
                this, it, 0,
                getString(R.string.autofill_unlock_title),
                getString(R.string.autofill_unlock_subtitle)
            )
        }
        if (inline != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAuthentication(ids, sender, presentation, inline)
        } else {
            builder.setAuthentication(ids, sender, presentation)
        }
        saveInfo(parsed)?.let { builder.setSaveInfo(it) }
        return builder.build()
    }

    /**
     * The response for an unlocked vault: a dataset per matching credential.
     *
     * A response with no datasets is still worth returning when it carries a
     * `SaveInfo` — that is the path where the user signs in to a site the vault
     * has never seen and is then offered the chance to save it.
     */
    private suspend fun unlockedResponse(
        parsed: ParsedStructure,
        matches: List<CredentialMatch>,
        inlineRequest: InlineSuggestionsRequest?
    ): FillResponse? {
        val key = SessionManager.key
        val builder = FillResponse.Builder()
        var datasets = 0

        if (key != null) {
            for ((index, match) in matches.take(MAX_DATASETS).withIndex()) {
                val detail = try {
                    repository.load(match.entry.id, key)
                } catch (e: Exception) {
                    // One unreadable row must not sink the whole response.
                    null
                } ?: continue

                val title = match.entry.groupLabel
                val subtitle = detail.username.ifBlank { getString(R.string.autofill_no_username) }
                val dataset = dataset(parsed, detail.username, detail.password, title, subtitle, inlineRequest, index)
                if (dataset != null) {
                    builder.addDataset(dataset)
                    datasets++
                }
            }
        }

        val save = saveInfo(parsed)
        if (datasets == 0 && save == null) return null
        save?.let { builder.setSaveInfo(it) }
        return builder.build()
    }

    private fun dataset(
        parsed: ParsedStructure,
        username: String,
        password: String,
        title: String,
        subtitle: String,
        inlineRequest: InlineSuggestionsRequest?,
        index: Int
    ): Dataset? {
        val builder = Dataset.Builder()
        val presentation = presentation(title, subtitle)
        val inline = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && inlineRequest != null) {
            InlinePresentations.build(this, inlineRequest, index, title, subtitle)
        } else {
            null
        }

        var any = false
        fun put(id: AutofillId, value: String) {
            val autofillValue = AutofillValue.forText(value)
            if (inline != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setValue(id, autofillValue, presentation, inline)
            } else {
                builder.setValue(id, autofillValue, presentation)
            }
            any = true
        }

        parsed.usernameFields.forEach { put(it.autofillId, username) }
        // A sign-up form's "new password" box is not somewhere an existing
        // password belongs; offering one there is how a user overwrites a fresh
        // credential with an old one without noticing.
        parsed.passwordFields
            .filter { it.type == FieldType.PASSWORD }
            .forEach { put(it.autofillId, password) }

        return if (any) builder.build() else null
    }

    // ── Save ───────────────────────────────────────────────────────────────

    /**
     * Asks the platform to offer a save prompt once the form is submitted.
     *
     * `FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE` is set because a great many login
     * screens never "submit" in a way the framework sees — they swap fragments,
     * or the WebView navigates — and without it the prompt simply never appears
     * on those.
     */
    private fun saveInfo(parsed: ParsedStructure): SaveInfo? {
        val passwordIds = parsed.passwordFields.map { it.autofillId }
        val usernameIds = parsed.usernameFields.map { it.autofillId }
        if (passwordIds.isEmpty()) return null

        val type = if (usernameIds.isEmpty()) {
            SaveInfo.SAVE_DATA_TYPE_PASSWORD
        } else {
            SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD
        }

        // The password is required; a username is optional, because a form that
        // collected the identifier on a previous screen still has a password
        // worth saving.
        return SaveInfo.Builder(type, passwordIds.toTypedArray())
            .apply { if (usernameIds.isNotEmpty()) setOptionalIds(usernameIds.toTypedArray()) }
            .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            .build()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onFailure(getString(R.string.autofill_save_failed))
            return
        }

        val parsed = StructureParser.parse(structure)
        val candidate = SaveCandidate.from(parsed)
        if (candidate == null) {
            callback.onFailure(getString(R.string.autofill_save_nothing))
            return
        }

        // Saving needs the vault key and a decision about which service this
        // belongs to, so it always goes through an activity. Doing it silently
        // would mean either writing while locked — impossible — or guessing at a
        // service mapping the user never saw.
        val intent = AutofillSaveActivity.intent(this, PendingSaves.offer(candidate))
        callback.onSuccess(
            PendingIntent.getActivity(
                this,
                candidate.token.hashCode(),
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            ).intentSender
        )
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun presentation(title: String, subtitle: String?): RemoteViews =
        RemoteViews(packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.tvTitle, title)
            setTextViewText(R.id.tvSubtitle, subtitle.orEmpty())
        }

    private fun inlineRequestOf(request: FillRequest): InlineSuggestionsRequest? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) request.inlineSuggestionsRequest else null
}
