package com.safevault.app.credential

import android.app.PendingIntent
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs
import com.safevault.app.ui.UnlockActivity
import kotlinx.coroutines.launch

class SafeVaultCredentialGetActivity : AppCompatActivity() {

    private val repository by lazy { VaultRepository(this) }
    private val prefs by lazy { VaultPrefs(this) }
    private lateinit var unlock: androidx.activity.result.ActivityResultLauncher<Intent>

    companion object {
        private const val EXTRA_KIND = "kind"
        private const val EXTRA_ID = "id"

        fun pendingIntent(context: Context, kind: String, id: Long): PendingIntent =
            PendingIntent.getActivity(
                context,
                ("$kind:$id").hashCode(),
                Intent(context, SafeVaultCredentialGetActivity::class.java)
                    .putExtra(EXTRA_KIND, kind)
                    .putExtra(EXTRA_ID, id),
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
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
        val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val key = SessionManager.key
        if (providerRequest == null || key == null) {
            fail()
            return
        }

        lifecycleScope.launch {
            when (intent.getStringExtra(EXTRA_KIND)) {
                "password" -> {
                    val detail = repository.load(intent.getLongExtra(EXTRA_ID, 0L), key)
                    if (detail == null) {
                        fail()
                    } else {
                        repository.markUsed(detail.entry.id)
                        succeed(GetCredentialResponse(PasswordCredential(detail.username, detail.password)))
                    }
                }
                "passkey" -> {
                    val detail = repository.loadPasskey(intent.getLongExtra(EXTRA_ID, 0L), key)
                    val option = providerRequest.credentialOptions
                        .filterIsInstance<androidx.credentials.GetPublicKeyCredentialOption>()
                        .firstOrNull()
                    if (detail == null || option == null) {
                        fail()
                        return@launch
                    }
                    val request = try {
                        WebAuthn.parseRequestOptions(option.requestJson)
                    } catch (e: Exception) {
                        fail()
                        return@launch
                    }
                    if (request.rpId != detail.passkey.rpId ||
                        (request.allowedCredentialIds.isNotEmpty() &&
                            detail.passkey.credentialId !in request.allowedCredentialIds)
                    ) {
                        fail()
                        return@launch
                    }

                    val origin = WebAuthn.originFor(providerRequest.callingAppInfo)
                    val json = WebAuthn.getCredentialJson(
                        options = request,
                        origin = origin,
                        packageName = providerRequest.callingAppInfo.packageName,
                        credentialId = detail.passkey.credentialId,
                        userHandle = detail.userHandle,
                        privateKey = WebAuthn.privateKeyFromBase64Url(detail.privateKey),
                        signCount = detail.passkey.signCount + 1,
                        clientDataHash = option.clientDataHash
                    )
                    repository.markPasskeyUsed(detail.passkey.id)
                    succeed(GetCredentialResponse(PublicKeyCredential(json)))
                }
                else -> fail()
            }
        }
    }

    private fun succeed(response: GetCredentialResponse) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, response)
        setResult(RESULT_OK, result)
        finish()
    }

    private fun fail() {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(
            result,
            GetCredentialUnknownException(getString(com.safevault.app.R.string.credential_provider_failed))
        )
        setResult(RESULT_OK, result)
        finish()
    }
}
