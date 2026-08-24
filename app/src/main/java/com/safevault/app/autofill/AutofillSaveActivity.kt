package com.safevault.app.autofill

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.data.CredentialDraft
import com.safevault.app.data.UriBinding
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultRepository
import com.safevault.app.databinding.DialogAutofillSaveBinding
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs
import com.safevault.app.ui.UnlockActivity
import kotlinx.coroutines.launch

/**
 * Writes a credential the user just typed somewhere else into the vault.
 *
 * The platform has already asked "save this password?" and been told yes by the
 * time this runs, so this screen does not ask again. What it does ask is the one
 * thing the platform cannot: **which service is this?** Getting that wrong is not
 * cosmetic — the service owns the URI bindings, so a login filed under the wrong
 * one will later be offered on the wrong site.
 *
 * The answer is pre-filled from an existing binding where one matches, which is
 * the common case for a password change on a site already in the vault. Where
 * nothing matches, the registrable domain is a good enough first guess and the
 * field is editable.
 *
 * Saving needs the vault key, so a locked vault unlocks first — through the same
 * [UnlockActivity] the fill path uses.
 */
class AutofillSaveActivity : AppCompatActivity() {

    private val repository by lazy { VaultRepository(this) }
    private val prefs by lazy { VaultPrefs(this) }

    private var candidate: SaveCandidate? = null
    private lateinit var unlock: androidx.activity.result.ActivityResultLauncher<Intent>

    companion object {
        private const val EXTRA_TOKEN = "save_token"

        /** The intent carries a token, never the credential — see [SaveCandidate]. */
        fun intent(context: Context, token: String): Intent =
            Intent(context, AutofillSaveActivity::class.java)
                .putExtra(EXTRA_TOKEN, token)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Taken, not read: a candidate is consumed once. A configuration change
        // would otherwise re-take an already-consumed token and find nothing, so
        // the value is held on the instance from here on.
        candidate = PendingSaves.take(intent.getStringExtra(EXTRA_TOKEN))
        if (candidate == null) {
            finish()
            return
        }

        unlock = registerForActivityResult(
            androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK &&
                SessionManager.isUnlockedWithin(prefs.autoLockMs)
            ) {
                promptForService()
            } else {
                finish()
            }
        }

        if (SessionManager.isUnlockedWithin(prefs.autoLockMs)) {
            promptForService()
        } else {
            unlock.launch(UnlockActivity.forResult(this))
        }
    }

    private fun promptForService() {
        val candidate = this.candidate ?: return finish()
        val key = SessionManager.key ?: return finish()

        lifecycleScope.launch {
            val existingService = repository.serviceForTarget(candidate.webHost, candidate.packageName)
            val existingEntry = existingService?.let {
                repository.findAccount(it.id, candidate.username, key)
            }

            val binding = DialogAutofillSaveBinding.inflate(layoutInflater)
            binding.etService.setText(existingService?.name ?: suggestServiceName(candidate))
            binding.tvSummary.text = when {
                existingEntry != null ->
                    getString(R.string.autofill_save_update, candidate.username)
                candidate.username.isBlank() ->
                    getString(R.string.autofill_save_new_no_user)
                else ->
                    getString(R.string.autofill_save_new, candidate.username)
            }
            binding.tvTarget.text = if (candidate.webHost.isNotEmpty()) {
                getString(R.string.autofill_save_target_web, candidate.webHost)
            } else {
                getString(R.string.autofill_save_target_app, candidate.packageName)
            }

            AlertDialog.Builder(this@AutofillSaveActivity)
                .setTitle(
                    if (existingEntry != null) R.string.autofill_update_title
                    else R.string.autofill_save_title
                )
                .setView(binding.root)
                .setPositiveButton(R.string.save) { _, _ ->
                    commit(binding.etService.text?.toString().orEmpty(), existingEntry)
                }
                .setNegativeButton(android.R.string.cancel) { _, _ -> finish() }
                .setOnCancelListener { finish() }
                .show()
        }
    }

    private fun commit(serviceName: String, existingEntry: VaultEntry?) {
        val candidate = this.candidate ?: return finish()
        val key = SessionManager.key ?: return finish()

        lifecycleScope.launch {
            val ok = try {
                val name = serviceName.trim().ifBlank { suggestServiceName(candidate) }

                repository.save(
                    CredentialDraft(
                        // A matching account is updated in place; anything else is
                        // a new row. Overwriting the wrong account would destroy a
                        // password, so this only ever reuses an id that was found
                        // by an exact username match on an already-bound service.
                        id = existingEntry?.id ?: 0L,
                        title = existingEntry?.title ?: name,
                        serviceName = name,
                        website = if (candidate.webHost.isNotEmpty()) candidate.webHost
                            else existingEntry?.website.orEmpty(),
                        username = candidate.username,
                        password = candidate.password,
                        // The autofill flow never sees notes, so an update must
                        // carry the existing ones forward rather than blank them.
                        notes = existingEntry?.let { repository.load(it.id, key)?.notes }.orEmpty(),
                        favorite = existingEntry?.favorite ?: false
                    ),
                    key
                )

                // Teach the vault where this credential came from, so the next
                // visit fills without being asked again.
                val serviceId = repository.resolveService(name)
                if (candidate.webHost.isNotEmpty()) {
                    repository.bindWebsite(serviceId, candidate.webHost, UriBinding.SOURCE_AUTOFILL)
                } else {
                    repository.bindPackage(serviceId, candidate.packageName, UriBinding.SOURCE_AUTOFILL)
                }
                true
            } catch (e: Exception) {
                false
            }

            val message = when {
                !ok -> R.string.autofill_save_error
                existingEntry != null -> R.string.autofill_updated
                else -> R.string.autofill_saved
            }
            Toast.makeText(this@AutofillSaveActivity, message, Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    /**
     * A first guess at the service name: the registrable domain for a web form,
     * or the last meaningful label of the package for an app.
     *
     * `com.google.android.gm` suggests "gm", which is poor — but the field is
     * editable and a wrong guess the user corrects is better than a blank field
     * they must fill in from nothing.
     */
    private fun suggestServiceName(candidate: SaveCandidate): String =
        if (candidate.webHost.isNotEmpty()) {
            UriNormalizer.registrableDomain(candidate.webHost)
        } else {
            candidate.packageName.substringAfterLast('.').ifBlank { candidate.packageName }
        }
}
