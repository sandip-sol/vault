package com.safevault.app.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.backup.BackupManager
import com.safevault.app.backup.BackupPackage
import com.safevault.app.data.VaultRepository
import com.safevault.app.databinding.ActivitySecurityBinding
import com.safevault.app.security.PasswordHealth
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultKeyManager
import com.safevault.app.security.VaultPrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/**
 * The Security screen from roadmap section 5: what state the vault is in, and the
 * few controls that change it. Every number shown here is derived on-device.
 */
class SecurityActivity : SecureActivity() {

    private lateinit var binding: ActivitySecurityBinding
    private lateinit var repository: VaultRepository
    private lateinit var keys: VaultKeyManager
    private lateinit var prefs: VaultPrefs
    private lateinit var backups: BackupManager

    /** Held between the passphrase prompt and the file picker returning. */
    private var pendingBackupPassphrase: CharArray? = null

    private val createBackupFile = registerForActivityResult(
        ActivityResultContracts.CreateDocument(BackupPackage.MIME_TYPE)
    ) { uri -> if (uri != null) writeBackup(uri) else clearPendingPassphrase() }

    private val pickBackupFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let(::promptRestore) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isFinishing) return

        binding = ActivitySecurityBinding.inflate(layoutInflater)
        setContentView(binding.root)
        repository = VaultRepository(this)
        keys = VaultKeyManager(this)
        prefs = VaultPrefs(this)
        backups = BackupManager(this)

        binding.toolbar.setNavigationOnClickListener { finish() }
        binding.btnCreateBackup.setOnClickListener { promptBackupPassphrase() }
        binding.btnRestoreBackup.setOnClickListener { confirmRestore() }
        binding.btnImportCsv.setOnClickListener {
            startActivity(Intent(this, ImportActivity::class.java))
        }
        binding.btnChangePassword.setOnClickListener { promptChangeMasterPassword() }

        setUpAutoLock()
        setUpBiometricSwitch()
        binding.tvPrivacyDetail.setText(R.string.privacy_detail)
    }

    override fun onResume() {
        super.onResume()
        if (isFinishing) return
        refreshHealth()
        refreshBackupStatus()
        // Autofill is enabled in system settings, not here, so the state has to
        // be re-read every time this screen comes back rather than cached.
        refreshAutofillStatus()
    }

    // -- Autofill -----------------------------------------------------------

    /**
     * Reflects the *system's* view of who the autofill service is.
     *
     * There is no in-app switch for this on purpose. Only the user, in Settings,
     * can appoint an autofill service — an app cannot appoint itself — so a
     * switch here would be a control that does not control anything. The button
     * opens the settings screen and the text says what is currently true.
     */
    private fun refreshAutofillStatus() {
        val manager = getSystemService(AutofillManager::class.java)
        if (manager == null || !manager.isAutofillSupported) {
            binding.tvAutofillNote.setText(R.string.autofill_unsupported_note)
            binding.btnAutofill.isEnabled = false
            return
        }

        val enabled = manager.hasEnabledAutofillServices()
        binding.tvAutofillNote.setText(
            if (enabled) R.string.autofill_enabled_note else R.string.autofill_disabled_note
        )
        binding.btnAutofill.isEnabled = true
        binding.btnAutofill.setText(
            if (enabled) R.string.autofill_open_settings else R.string.autofill_enable
        )
        binding.btnAutofill.setOnClickListener {
            if (enabled) openAutofillSettings() else requestAutofillService(manager)
        }
    }

    /**
     * Asks the system to make SafeVault the autofill service. The dialog is the
     * platform's, and declining it is a normal outcome rather than an error.
     */
    private fun requestAutofillService(manager: AutofillManager) {
        val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
            .setData(Uri.parse("package:$packageName"))
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            openAutofillSettings()
        }
    }

    private fun openAutofillSettings() {
        try {
            startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE))
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, R.string.autofill_unsupported_note, Toast.LENGTH_LONG).show()
        }
    }

    // -- Health -------------------------------------------------------------

    private fun refreshHealth() {
        lifecycleScope.launch {
            val entries = repository.getAll()
            val weak = entries.count { it.strengthScore in 1..PasswordHealth.SCORE_WEAK }
            val reused = entries
                .filter { it.reuseHash.isNotEmpty() }
                .groupingBy { it.reuseHash }
                .eachCount()
                .filterValues { it > 1 }
                .values.sum()

            binding.statTotal.tvStatValue.text = entries.size.toString()
            binding.statTotal.tvStatLabel.setText(R.string.stat_stored)
            binding.statWeak.tvStatValue.text = weak.toString()
            binding.statWeak.tvStatLabel.setText(R.string.stat_weak)
            binding.statReused.tvStatValue.text = reused.toString()
            binding.statReused.tvStatLabel.setText(R.string.stat_reused)

            binding.tvHealthNote.setText(
                if (weak + reused == 0) R.string.health_clean else R.string.health_action
            )
        }
    }

    // -- Backup -------------------------------------------------------------

    private fun refreshBackupStatus() {
        val last = prefs.lastBackupAt
        binding.tvBackupStatus.text = if (last == 0L) {
            getString(R.string.backup_never)
        } else {
            val formatter = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
            getString(R.string.backup_last, formatter.format(Date(last)))
        }
    }

    private fun promptBackupPassphrase() {
        PassphraseDialog.show(
            context = this,
            title = getString(R.string.create_backup),
            note = getString(R.string.backup_passphrase_note),
            fields = listOf(
                PassphraseDialog.Field(getString(R.string.backup_passphrase)),
                PassphraseDialog.Field(getString(R.string.confirm_passphrase))
            ),
            positiveText = getString(R.string.choose_file),
            validate = { values ->
                when {
                    values[0].length < 8 -> 0 to getString(R.string.error_password_short)
                    values[0] != values[1] -> 1 to getString(R.string.error_password_mismatch)
                    else -> null
                }
            }
        ) { values ->
            pendingBackupPassphrase = values[0].toCharArray()
            createBackupFile.launch(backups.suggestedFileName())
        }
    }

    private fun writeBackup(destination: Uri) {
        val passphrase = pendingBackupPassphrase ?: return
        val dek = SessionManager.key ?: return
        pendingBackupPassphrase = null

        lifecycleScope.launch {
            when (val result = backups.export(destination, passphrase, dek)) {
                is BackupManager.ExportResult.Success -> {
                    // An export that will not re-open is not a backup, so the two
                    // outcomes get different words rather than one cheerful tick.
                    val message = if (result.verified) {
                        getString(R.string.backup_verified, result.entries)
                    } else {
                        getString(R.string.backup_unverified)
                    }
                    AlertDialog.Builder(this@SecurityActivity)
                        .setTitle(R.string.create_backup)
                        .setMessage(message)
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                    refreshBackupStatus()
                }

                is BackupManager.ExportResult.Failed ->
                    toast(getString(R.string.backup_failed, result.reason))
            }
            passphrase.fill(' ')
        }
    }

    private fun clearPendingPassphrase() {
        pendingBackupPassphrase?.fill(' ')
        pendingBackupPassphrase = null
    }

    private fun confirmRestore() {
        AlertDialog.Builder(this)
            .setTitle(R.string.restore_from_backup)
            .setMessage(R.string.restore_warning)
            .setPositiveButton(R.string.choose_file) { _, _ ->
                pickBackupFile.launch(arrayOf("*/*"))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun promptRestore(source: Uri) {
        lifecycleScope.launch {
            val header = try {
                withContext(Dispatchers.IO) { backups.inspect(source) }
            } catch (e: Exception) {
                toast(e.message ?: getString(R.string.restore_unreadable))
                return@launch
            }

            PassphraseDialog.show(
                context = this@SecurityActivity,
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
                    // The DEK is wrapped under a different password now; start clean.
                    SessionManager.lock()
                    startActivity(
                        Intent(this@SecurityActivity, UnlockActivity::class.java)
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

    // -- Unlock settings ----------------------------------------------------

    private fun setUpAutoLock() {
        val labels = VaultPrefs.AUTO_LOCK_CHOICES_MS.map(::autoLockLabel).toTypedArray()
        binding.spinnerAutoLock.setSimpleItems(labels)
        binding.spinnerAutoLock.setText(autoLockLabel(prefs.autoLockMs), false)
        binding.spinnerAutoLock.setOnItemClickListener { _, _, position, _ ->
            prefs.autoLockMs = VaultPrefs.AUTO_LOCK_CHOICES_MS[position]
        }
    }

    private fun autoLockLabel(ms: Long): String {
        val seconds = (ms / 1000).toInt()
        return if (seconds < 60) {
            resources.getQuantityString(R.plurals.seconds, seconds, seconds)
        } else {
            val minutes = seconds / 60
            resources.getQuantityString(R.plurals.minutes, minutes, minutes)
        }
    }

    private fun setUpBiometricSwitch() {
        val available = BiometricManager.from(this).canAuthenticate(BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

        binding.switchBiometric.isChecked = keys.biometricEnabled
        binding.switchBiometric.isEnabled = available || keys.biometricEnabled
        binding.tvBiometricNote.setText(
            if (available) R.string.biometric_note else R.string.biometric_note_unavailable
        )

        binding.switchBiometric.setOnClickListener {
            if (binding.switchBiometric.isChecked) {
                enrollBiometric()
            } else {
                keys.disableBiometric()
                toast(getString(R.string.biometric_disabled))
            }
        }
    }

    /**
     * Enrollment authorises a Keystore cipher and seals the DEK with it, so the
     * only copy of the DEK outside the password envelope sits behind a key the
     * Keystore will not operate without a fresh Class 3 biometric match.
     */
    private fun enrollBiometric() {
        val dek = SessionManager.key
        if (dek == null) {
            binding.switchBiometric.isChecked = false
            return
        }

        val cipher = try {
            keys.biometricEnrollmentCipher()
        } catch (e: Exception) {
            binding.switchBiometric.isChecked = false
            toast(getString(R.string.biometric_unavailable))
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authorised = result.cryptoObject?.cipher
                    if (authorised == null) {
                        binding.switchBiometric.isChecked = false
                        return
                    }
                    keys.completeBiometricEnrollment(dek, authorised)
                    toast(getString(R.string.biometric_enabled))
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    binding.switchBiometric.isChecked = false
                }
            }
        )

        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.biometric_unlock))
                .setSubtitle(getString(R.string.biometric_enroll_subtitle))
                .setNegativeButtonText(getString(android.R.string.cancel))
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build(),
            BiometricPrompt.CryptoObject(cipher)
        )
    }

    private fun promptChangeMasterPassword() {
        PassphraseDialog.show(
            context = this,
            title = getString(R.string.change_master_password),
            note = getString(R.string.change_password_note),
            fields = listOf(
                PassphraseDialog.Field(getString(R.string.current_master_password)),
                PassphraseDialog.Field(getString(R.string.new_master_password)),
                PassphraseDialog.Field(getString(R.string.confirm_password))
            ),
            positiveText = getString(R.string.change),
            validate = { values ->
                when {
                    values[0].isEmpty() -> 0 to getString(R.string.error_password_empty)
                    values[1].length < 8 -> 1 to getString(R.string.error_password_short)
                    values[1] != values[2] -> 2 to getString(R.string.error_password_mismatch)
                    else -> null
                }
            }
        ) { values ->
            lifecycleScope.launch {
                val changed = withContext(Dispatchers.Default) {
                    keys.changeMasterPassword(values[0].toCharArray(), values[1].toCharArray())
                }
                if (changed) {
                    // The biometric envelope wraps the same DEK and would still
                    // work, but re-enrolling after a password change is the
                    // conservative default: the old envelope was authorised under
                    // the old secret.
                    keys.disableBiometric()
                    binding.switchBiometric.isChecked = false
                    toast(getString(R.string.password_changed))
                } else {
                    toast(getString(R.string.error_wrong_password))
                }
            }
        }
    }

    private fun toast(message: String) =
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}
