package com.safevault.app.ui

import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.data.VaultRepository
import com.safevault.app.databinding.ActivityImportBinding
import com.safevault.app.importer.CsvImport
import com.safevault.app.security.SessionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * CSV import from another password manager (PRD Phase 2 backlog).
 *
 * Two things the PRD asks for and this screen takes seriously:
 *
 *  - **Clear warnings.** A plaintext CSV of every password someone owns is the
 *    single most dangerous file they will ever create. The screen says so before
 *    the picker opens, not after the import succeeds.
 *  - **Post-import cleanup guidance.** The export is still sitting in Downloads
 *    when the import finishes, so the last screen is about deleting it.
 *
 * Import adds to the vault rather than replacing it, so running it twice
 * duplicates rather than destroys. Restore is the operation that replaces.
 */
class ImportActivity : SecureActivity() {

    private lateinit var binding: ActivityImportBinding
    private lateinit var repository: VaultRepository

    private var pending: CsvImport.Report? = null

    private val pickCsv = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let(::preview) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isFinishing) return

        binding = ActivityImportBinding.inflate(layoutInflater)
        setContentView(binding.root)
        repository = VaultRepository(this)

        binding.toolbar.setNavigationOnClickListener { finish() }
        binding.btnChooseFile.setOnClickListener {
            pickCsv.launch(arrayOf("text/csv", "text/comma-separated-values", "text/plain", "*/*"))
        }
        binding.btnImport.setOnClickListener { runImport() }
        showChooseState()
    }

    // ── States ─────────────────────────────────────────────────────────────

    private fun showChooseState() {
        binding.chooseSection.isVisible = true
        binding.previewSection.isVisible = false
        binding.btnImport.isVisible = false
    }

    private fun preview(source: Uri) {
        lifecycleScope.launch {
            val report = try {
                withContext(Dispatchers.IO) {
                    val text = contentResolver.openInputStream(source)?.use {
                        it.readBytes().toString(Charsets.UTF_8)
                    } ?: throw CsvImport.MalformedCsvException("Could not open the chosen file")
                    CsvImport.read(text)
                }
            } catch (e: CsvImport.MalformedCsvException) {
                toast(e.message ?: getString(R.string.import_unreadable))
                return@launch
            } catch (e: Exception) {
                toast(getString(R.string.import_unreadable))
                return@launch
            }

            if (report.imported == 0) {
                toast(getString(R.string.import_nothing_usable))
                return@launch
            }

            pending = report
            binding.chooseSection.isVisible = false
            binding.previewSection.isVisible = true
            binding.btnImport.isVisible = true

            binding.tvDetectedSource.text =
                getString(R.string.import_detected, report.mapping.source)
            binding.tvImportCount.text = resources.getQuantityString(
                R.plurals.import_ready, report.imported, report.imported
            )
            binding.tvSkipped.isVisible = report.skipped > 0
            binding.tvSkipped.text = getString(
                R.string.import_skipped, report.skippedNoPassword, report.skippedMalformed
            )
            binding.tvSample.text = report.drafts.take(5).joinToString("\n") { draft ->
                val user = draft.username.ifBlank { getString(R.string.import_no_username) }
                "${draft.title}  ·  $user"
            }
            binding.btnImport.text =
                resources.getQuantityString(R.plurals.import_action, report.imported, report.imported)
        }
    }

    private fun runImport() {
        val report = pending ?: return
        val key = SessionManager.key ?: return

        binding.btnImport.isEnabled = false
        lifecycleScope.launch {
            val added = try {
                withContext(Dispatchers.IO) {
                    report.drafts.forEach { repository.save(it, key) }
                    report.drafts.size
                }
            } catch (e: Exception) {
                binding.btnImport.isEnabled = true
                toast(getString(R.string.import_failed, e.message ?: ""))
                return@launch
            }
            showCleanupGuidance(added)
        }
    }

    /**
     * The import worked; the plaintext file it came from is the problem now.
     * This is the PRD's "post-import cleanup guidance", and it is a blocking
     * dialog rather than a toast because it is the only part of the flow the
     * app cannot do on the user's behalf.
     */
    private fun showCleanupGuidance(added: Int) {
        AlertDialog.Builder(this)
            .setTitle(resources.getQuantityString(R.plurals.import_done, added, added))
            .setMessage(R.string.import_cleanup_guidance)
            .setPositiveButton(R.string.import_understood) { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    private fun toast(message: String) =
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}
