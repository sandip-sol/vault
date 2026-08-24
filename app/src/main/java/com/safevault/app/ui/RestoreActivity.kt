package com.safevault.app.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.backup.BackupManager
import com.safevault.app.databinding.ActivityRestoreBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * First-run restore: the path for someone setting up a new device from an
 * encrypted backup, before any local vault exists.
 *
 * The same operation is available from the Security screen for an existing
 * vault; the difference here is that there is nothing to overwrite, so no
 * destructive-action warning is shown.
 */
class RestoreActivity : SecureActivity() {

    override val requiresUnlockedVault = false

    private lateinit var binding: ActivityRestoreBinding
    private lateinit var backups: BackupManager

    private val pickBackupFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) finish() else inspectAndPrompt(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityRestoreBinding.inflate(layoutInflater)
        setContentView(binding.root)
        backups = BackupManager(this)

        binding.toolbar.setNavigationOnClickListener { finish() }
        binding.btnChooseFile.setOnClickListener { pickBackupFile.launch(arrayOf("*/*")) }
    }

    private fun inspectAndPrompt(source: Uri) {
        lifecycleScope.launch {
            val header = try {
                withContext(Dispatchers.IO) { backups.inspect(source) }
            } catch (e: Exception) {
                toast(e.message ?: getString(R.string.restore_unreadable))
                return@launch
            }

            PassphraseDialog.show(
                context = this@RestoreActivity,
                title = getString(R.string.restore_from_backup),
                note = getString(R.string.restore_note, header.entryCount),
                fields = listOf(
                    PassphraseDialog.Field(getString(R.string.backup_passphrase)),
                    PassphraseDialog.Field(getString(R.string.new_master_password)),
                    PassphraseDialog.Field(getString(R.string.confirm_password))
                ),
                positiveText = getString(R.string.restore),
                validate = { values ->
                    when {
                        values[0].isEmpty() -> 0 to getString(R.string.error_password_empty)
                        values[1].length < 8 -> 1 to getString(R.string.error_password_short)
                        values[1] != values[2] -> 2 to getString(R.string.error_password_mismatch)
                        else -> null
                    }
                }
            ) { values -> runRestore(source, values[0], values[1]) }
        }
    }

    private fun runRestore(source: Uri, passphrase: String, newMaster: String) {
        lifecycleScope.launch {
            val result = backups.restore(
                source = source,
                passphrase = passphrase.toCharArray(),
                newMasterPassword = newMaster.toCharArray()
            )
            when (result) {
                is BackupManager.RestoreResult.Success -> {
                    toast(getString(R.string.restore_done, result.entries))
                    startActivity(
                        Intent(this@RestoreActivity, UnlockActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                    )
                    finish()
                }

                BackupManager.RestoreResult.WrongPassphrase ->
                    toast(getString(R.string.restore_wrong_passphrase))

                is BackupManager.RestoreResult.Failed ->
                    toast(getString(R.string.restore_failed, result.reason))
            }
        }
    }

    private fun toast(message: String) =
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}
