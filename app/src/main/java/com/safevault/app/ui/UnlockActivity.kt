package com.safevault.app.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.databinding.ActivityUnlockBinding
import com.safevault.app.security.LegacyVaultMigration
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

class UnlockActivity : SecureActivity() {

    override val requiresUnlockedVault = false

    private lateinit var binding: ActivityUnlockBinding
    private lateinit var keys: VaultKeyManager
    private var failedAttempts = 0
    private var biometricPromptShown = false

    companion object {
        private const val LOCKOUT_AFTER_ATTEMPTS = 3
        private const val LOCKOUT_MS = 5_000L
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityUnlockBinding.inflate(layoutInflater)
        setContentView(binding.root)
        keys = VaultKeyManager(this)

        if (keys.isInitialized) setupLoginMode() else setupCreateMode()
    }

    /**
     * Returning to the app from the launcher lands here even when the session is
     * still alive, so a live session is handed straight through to the vault.
     * Without this, coming back inside the auto-lock window still demanded the
     * master password, which made the auto-lock setting meaningless from the
     * home screen.
     *
     * The check belongs in onResume, not onCreate: SafeVaultApp evaluates the
     * timeout on the process ON_START that fires between the two, so onCreate can
     * still see a session that is about to be locked.
     */
    override fun onResume() {
        super.onResume()
        if (SessionManager.isUnlocked) {
            startActivity(Intent(this, VaultActivity::class.java))
            finish()
        }
    }

    // ── First run ──────────────────────────────────────────────────────────

    private fun setupCreateMode() {
        binding.tvTitle.text = getString(R.string.create_master_password)
        binding.tvSubtitle.text = getString(R.string.create_master_hint)
        binding.tilConfirm.visibility = View.VISIBLE
        binding.btnBiometric.visibility = View.GONE
        binding.btnRestore.visibility = View.VISIBLE
        binding.btnUnlock.text = getString(R.string.create_vault)

        binding.btnRestore.setOnClickListener {
            startActivity(Intent(this, RestoreActivity::class.java))
        }

        binding.btnUnlock.setOnClickListener {
            val pass = binding.etPassword.text?.toString().orEmpty()
            val confirm = binding.etConfirm.text?.toString().orEmpty()
            when {
                pass.length < 8 ->
                    binding.tilPassword.error = getString(R.string.error_password_short)
                pass != confirm ->
                    binding.tilConfirm.error = getString(R.string.error_password_mismatch)
                else -> {
                    clearErrors()
                    setLoading(true)
                    lifecycleScope.launch {
                        val dek = withContext(Dispatchers.Default) {
                            keys.createVault(pass.toCharArray())
                        }
                        onUnlocked(dek)
                    }
                }
            }
        }
    }

    // ── Returning user ─────────────────────────────────────────────────────

    private fun setupLoginMode() {
        binding.tvTitle.text = getString(R.string.unlock_vault)
        binding.tvSubtitle.text = getString(R.string.enter_master_password)
        binding.tilConfirm.visibility = View.GONE
        binding.btnRestore.visibility = View.GONE
        binding.btnUnlock.text = getString(R.string.unlock)

        // A new fingerprint enrollment destroys the Keystore key on purpose, so
        // the envelope can outlive the key that opens it. Say so, once.
        if (keys.biometricNeedsReenrollment()) {
            keys.disableBiometric()
            Toast.makeText(this, R.string.biometric_invalidated, Toast.LENGTH_LONG).show()
        }

        val canUseBiometric = keys.biometricEnabled && strongBiometricAvailable()
        binding.btnBiometric.visibility = if (canUseBiometric) View.VISIBLE else View.GONE
        binding.btnBiometric.setOnClickListener { showBiometricPrompt() }

        binding.btnUnlock.setOnClickListener { attemptPasswordUnlock() }

        // Not while a session is still live — onResume is about to hand through.
        if (canUseBiometric && !biometricPromptShown && !SessionManager.isUnlocked) {
            biometricPromptShown = true
            showBiometricPrompt()
        }
    }

    private fun attemptPasswordUnlock() {
        val pass = binding.etPassword.text?.toString().orEmpty()
        if (pass.isEmpty()) {
            binding.tilPassword.error = getString(R.string.error_password_empty)
            return
        }
        clearErrors()
        setLoading(true)

        lifecycleScope.launch {
            val chars = pass.toCharArray()

            // A pre-envelope vault is upgraded here, while the password is in hand.
            when (val migration = LegacyVaultMigration.runIfNeeded(this@UnlockActivity, chars)) {
                is LegacyVaultMigration.Result.Failed -> {
                    setLoading(false)
                    Toast.makeText(
                        this@UnlockActivity,
                        getString(R.string.migration_failed),
                        Toast.LENGTH_LONG
                    ).show()
                    return@launch
                }
                is LegacyVaultMigration.Result.WrongPassword -> {
                    onWrongPassword()
                    return@launch
                }
                is LegacyVaultMigration.Result.Migrated -> {
                    Toast.makeText(
                        this@UnlockActivity,
                        getString(R.string.migration_done, migration.entries),
                        Toast.LENGTH_LONG
                    ).show()
                }
                LegacyVaultMigration.Result.NotNeeded -> Unit
            }

            val dek = withContext(Dispatchers.Default) { keys.unlockWithPassword(chars) }
            if (dek != null) {
                failedAttempts = 0
                onUnlocked(dek)
            } else {
                onWrongPassword()
            }
        }
    }

    private fun onWrongPassword() {
        setLoading(false)
        failedAttempts++
        binding.tilPassword.error = getString(R.string.error_wrong_password)
        if (failedAttempts >= LOCKOUT_AFTER_ATTEMPTS) {
            binding.btnUnlock.isEnabled = false
            binding.root.postDelayed({ binding.btnUnlock.isEnabled = true }, LOCKOUT_MS)
            Toast.makeText(this, R.string.too_many_attempts, Toast.LENGTH_SHORT).show()
        }
    }

    // ── Biometrics ─────────────────────────────────────────────────────────

    /**
     * Class 3 only. A Class 2 (weak) biometric cannot authorise a Keystore key,
     * so accepting one here would mean the fingerprint gate had no cryptographic
     * effect — which is precisely the flaw this replaced.
     */
    private fun strongBiometricAvailable(): Boolean =
        BiometricManager.from(this).canAuthenticate(BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    private fun showBiometricPrompt() {
        val cipher = keys.biometricUnlockCipher()
        if (cipher == null) {
            keys.disableBiometric()
            binding.btnBiometric.visibility = View.GONE
            Toast.makeText(this, R.string.biometric_invalidated, Toast.LENGTH_LONG).show()
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authorised = result.cryptoObject?.cipher ?: return
                    val dek = keys.completeBiometricUnlock(authorised)
                    if (dek != null) {
                        onUnlocked(dek)
                    } else {
                        keys.disableBiometric()
                        Toast.makeText(
                            this@UnlockActivity,
                            R.string.biometric_invalidated,
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (code == BiometricPrompt.ERROR_LOCKOUT ||
                        code == BiometricPrompt.ERROR_LOCKOUT_PERMANENT
                    ) {
                        Toast.makeText(
                            this@UnlockActivity,
                            R.string.biometric_locked_out,
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }
            }
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.app_name))
            .setSubtitle(getString(R.string.biometric_subtitle))
            .setNegativeButtonText(getString(R.string.use_password))
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    // ── Shared ─────────────────────────────────────────────────────────────

    private fun onUnlocked(dek: SecretKey) {
        SessionManager.unlock(dek)
        startActivity(Intent(this, VaultActivity::class.java))
        finish()
    }

    private fun clearErrors() {
        binding.tilPassword.error = null
        binding.tilConfirm.error = null
    }

    private fun setLoading(loading: Boolean) {
        binding.progress.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnUnlock.isEnabled = !loading
    }
}
