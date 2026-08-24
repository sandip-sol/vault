package com.safevault.app.autofill

import android.app.Activity
import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.data.CredentialMatch
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs
import com.safevault.app.ui.UnlockActivity
import kotlinx.coroutines.launch

/**
 * The bridge between a locked vault and a fill request.
 *
 * The autofill service answers a locked request with a single authentication
 * entry pointing here. Only once this activity has an unlocked session does the
 * vault get queried at all — which is what stops the dropdown from revealing
 * whether a credential exists for a site the user cannot open the vault for.
 *
 * It has no UI of its own. Unlocking is [UnlockActivity]'s job, launched for a
 * result, so the lockout counter, the Class 3 biometric requirement and the
 * legacy-vault migration are the same code that runs at the front door.
 *
 * The result handed back is a [FillResponse], not a [Dataset]: the platform
 * replaces the whole response with it, so the user gets the normal list of
 * matching accounts to choose from rather than being given whichever one the
 * vault happened to rank first.
 */
class AutofillAuthActivity : AppCompatActivity() {

    private val repository by lazy { VaultRepository(this) }
    private val prefs by lazy { VaultPrefs(this) }

    private lateinit var unlock: androidx.activity.result.ActivityResultLauncher<Intent>

    companion object {
        private const val MAX_DATASETS = 8

        /**
         * @param requestCode distinguishes concurrent requests so two forms do not
         *   share — and overwrite — one another's PendingIntent.
         */
        fun intentSender(context: Context, requestCode: Int): IntentSender =
            PendingIntent.getActivity(
                context,
                requestCode,
                Intent(context, AutofillAuthActivity::class.java),
                // MUTABLE because the platform fills in EXTRA_ASSIST_STRUCTURE and
                // the client state before starting us. Nothing sensitive is put in
                // the intent by us, so there is nothing here for that to expose.
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
            ).intentSender
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Nothing secret is drawn here, but this activity is the visible step of
        // a flow that ends in credentials, and the unlock screen it launches is
        // FLAG_SECURE too. Being inconsistent about it invites a screenshot of
        // whatever transition state exists between them.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setResult(RESULT_CANCELED)

        unlock = registerForActivityResult(
            androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK &&
                SessionManager.isUnlockedWithin(prefs.autoLockMs)
            ) {
                respond()
            } else {
                finish()
            }
        }

        if (SessionManager.isUnlockedWithin(prefs.autoLockMs)) {
            // The session came back to life while the dropdown was open — for
            // instance the user unlocked the app in another window.
            respond()
        } else {
            unlock.launch(UnlockActivity.forResult(this))
        }
    }

    /** Builds the real response, now that there is a key to build it with. */
    private fun respond() {
        val structure = assistStructure()
        if (structure == null) {
            finish()
            return
        }

        val parsed = StructureParser.parse(structure)
        if (!parsed.fillable || parsed.packageName == packageName) {
            finish()
            return
        }

        lifecycleScope.launch {
            val key = SessionManager.key
            val matches = if (key == null) {
                emptyList()
            } else if (parsed.isWebRequest) {
                repository.matchesForHost(parsed.webHost)
            } else {
                repository.matchesForPackage(parsed.packageName)
            }

            val response = if (key == null) null else buildResponse(parsed, matches, key)
            setResult(
                RESULT_OK,
                Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
            )
            finish()
        }
    }

    private suspend fun buildResponse(
        parsed: ParsedStructure,
        matches: List<CredentialMatch>,
        key: javax.crypto.SecretKey
    ): FillResponse? {
        val builder = FillResponse.Builder()
        var added = 0

        for (match in matches.take(MAX_DATASETS)) {
            val detail = try {
                repository.load(match.entry.id, key)
            } catch (e: Exception) {
                null
            } ?: continue

            val presentation = RemoteViews(packageName, R.layout.autofill_dataset).apply {
                setTextViewText(R.id.tvTitle, match.entry.groupLabel)
                setTextViewText(
                    R.id.tvSubtitle,
                    detail.username.ifBlank { getString(R.string.autofill_no_username) }
                )
            }

            val dataset = Dataset.Builder()
            var any = false
            fun put(id: AutofillId, value: String) {
                dataset.setValue(id, AutofillValue.forText(value), presentation)
                any = true
            }
            parsed.usernameFields.forEach { put(it.autofillId, detail.username) }
            parsed.passwordFields
                .filter { it.type == FieldType.PASSWORD }
                .forEach { put(it.autofillId, detail.password) }

            if (any) {
                builder.addDataset(dataset.build())
                added++
                repository.markUsed(match.entry.id)
            }
        }

        val save = saveInfo(parsed)
        if (added == 0 && save == null) return null
        save?.let { builder.setSaveInfo(it) }
        return builder.build()
    }

    /**
     * Carries the save prompt through authentication.
     *
     * The locked response already had a SaveInfo, but an authenticated response
     * replaces it. Without repeating the save contract here, "unlock, then submit
     * a new password" would fill correctly and then never offer to save.
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

        return SaveInfo.Builder(type, passwordIds.toTypedArray())
            .apply { if (usernameIds.isNotEmpty()) setOptionalIds(usernameIds.toTypedArray()) }
            .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            .build()
    }

    @Suppress("DEPRECATION")
    private fun assistStructure(): AssistStructure? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(
                AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java
            )
        } else {
            intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }
}
