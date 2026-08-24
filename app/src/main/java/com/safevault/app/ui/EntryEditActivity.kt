package com.safevault.app.ui

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.data.CredentialDraft
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultRepository
import com.safevault.app.databinding.ActivityEntryEditBinding
import com.safevault.app.security.PasswordHealth
import com.safevault.app.security.SessionManager
import kotlinx.coroutines.launch

class EntryEditActivity : SecureActivity() {

    companion object {
        const val EXTRA_ID = "entry_id"
    }

    private lateinit var binding: ActivityEntryEditBinding
    private lateinit var repository: VaultRepository
    private var existing: VaultEntry? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isFinishing) return

        binding = ActivityEntryEditBinding.inflate(layoutInflater)
        setContentView(binding.root)
        repository = VaultRepository(this)

        binding.toolbar.setNavigationOnClickListener { finish() }
        binding.btnGenerate.setOnClickListener {
            binding.etPassword.setText(PasswordGenerator.generate())
        }
        binding.btnCopyUser.setOnClickListener {
            copy(R.string.copy_username, binding.etUsername.text?.toString().orEmpty())
        }
        binding.btnCopyPass.setOnClickListener {
            copy(R.string.copy_password, binding.etPassword.text?.toString().orEmpty())
        }
        binding.btnSave.setOnClickListener { save() }

        binding.etPassword.doAfterTextChanged { showStrength(it?.toString().orEmpty()) }
        showStrength("")

        loadServiceSuggestions()

        val id = intent.getLongExtra(EXTRA_ID, -1L)
        if (id > 0) loadEntry(id) else binding.toolbar.setTitle(R.string.new_entry)
    }

    /** Offers services already in the vault so grouping stays consistent. */
    private fun loadServiceSuggestions() {
        lifecycleScope.launch {
            val services = repository.getAll()
                .map { it.groupLabel }
                .filter { it.isNotBlank() }
                .distinct()
                .sorted()
            binding.etService.setAdapter(
                ArrayAdapter(
                    this@EntryEditActivity,
                    android.R.layout.simple_list_item_1,
                    services
                )
            )
        }
    }

    private fun loadEntry(id: Long) {
        binding.toolbar.setTitle(R.string.edit_entry)
        lifecycleScope.launch {
            val key = SessionManager.key ?: return@launch finish()
            val detail = try {
                repository.load(id, key)
            } catch (e: Exception) {
                null
            }
            if (detail == null) {
                Toast.makeText(this@EntryEditActivity, R.string.decrypt_failed, Toast.LENGTH_SHORT)
                    .show()
                finish()
                return@launch
            }

            existing = detail.entry
            with(binding) {
                etTitle.setText(detail.entry.title)
                etService.setText(detail.entry.serviceName, false)
                etWebsite.setText(detail.entry.website)
                etUsername.setText(detail.username)
                etPassword.setText(detail.password)
                etNotes.setText(detail.notes)
                cbFavorite.isChecked = detail.entry.favorite
            }
        }
    }

    private fun save() {
        val key = SessionManager.key ?: return finish()
        val title = binding.etTitle.text?.toString()?.trim().orEmpty()
        val password = binding.etPassword.text?.toString().orEmpty()

        if (title.isEmpty()) {
            binding.tilTitle.error = getString(R.string.error_title_required)
            return
        }
        if (password.isEmpty()) {
            binding.tilPassword.error = getString(R.string.error_password_empty)
            return
        }
        binding.tilTitle.error = null
        binding.tilPassword.error = null

        val draft = CredentialDraft(
            id = existing?.id ?: 0,
            title = title,
            // An entry with no service given groups under its own title.
            serviceName = binding.etService.text?.toString()?.trim().orEmpty().ifBlank { title },
            website = binding.etWebsite.text?.toString()?.trim().orEmpty(),
            username = binding.etUsername.text?.toString().orEmpty(),
            password = password,
            notes = binding.etNotes.text?.toString().orEmpty(),
            favorite = binding.cbFavorite.isChecked
        )

        lifecycleScope.launch {
            repository.save(draft, key)
            Toast.makeText(this@EntryEditActivity, R.string.saved, Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    private fun showStrength(password: String) {
        val score = PasswordHealth.score(password)
        binding.strengthBar.progress = score
        binding.tvStrength.text = if (password.isEmpty()) "" else PasswordHealth.label(score)
    }

    private fun copy(labelRes: Int, value: String) {
        val label = getString(labelRes)
        if (SecureClipboard.copySensitive(this, label, value)) {
            Toast.makeText(
                this,
                getString(R.string.copied_autoclear, SecureClipboard.CLEAR_DELAY_MS / 1000),
                Toast.LENGTH_SHORT
            ).show()
        }
    }
}
