package com.safevault.app.credential

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs
import com.safevault.app.ui.UnlockActivity
import kotlinx.coroutines.launch

class SafeVaultCredentialAuthActivity : AppCompatActivity() {

    private val repository by lazy { VaultRepository(this) }
    private val prefs by lazy { VaultPrefs(this) }
    private lateinit var unlock: androidx.activity.result.ActivityResultLauncher<Intent>

    companion object {
        fun pendingIntent(context: Context, requestCode: Int): PendingIntent =
            PendingIntent.getActivity(
                context,
                requestCode,
                Intent(context, SafeVaultCredentialAuthActivity::class.java),
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
            )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
            respond()
        } else {
            unlock.launch(UnlockActivity.forResult(this))
        }
    }

    private fun respond() {
        val request = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
        if (request == null) {
            finish()
            return
        }
        lifecycleScope.launch {
            val response = CredentialProviderResponses.unlocked(
                this@SafeVaultCredentialAuthActivity,
                repository,
                request
            )
            val result = Intent()
            PendingIntentHandler.setBeginGetCredentialResponse(result, response)
            setResult(RESULT_OK, result)
            finish()
        }
    }
}
