package com.safevault.app.credential

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import com.safevault.app.R
import com.safevault.app.autofill.UriNormalizer
import com.safevault.app.data.CredentialDraft
import com.safevault.app.data.PasskeyDraft
import com.safevault.app.data.UriBinding
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs
import com.safevault.app.ui.UnlockActivity
import kotlinx.coroutines.launch

class SafeVaultCredentialCreateActivity : AppCompatActivity() {

    private val repository by lazy { VaultRepository(this) }
    private val prefs by lazy { VaultPrefs(this) }
    private lateinit var unlock: androidx.activity.result.ActivityResultLauncher<Intent>

    companion object {
        fun pendingIntent(context: Context, requestCode: Int): PendingIntent =
            PendingIntent.getActivity(
                context,
                requestCode,
                Intent(context, SafeVaultCredentialCreateActivity::class.java),
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
                save()
            } else {
                finish()
            }
        }

        if (SessionManager.isUnlockedWithin(prefs.autoLockMs)) {
            save()
        } else {
            unlock.launch(UnlockActivity.forResult(this))
        }
    }

    private fun save() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val key = SessionManager.key
        if (request == null || key == null) {
            failUnknown()
            return
        }

        lifecycleScope.launch {
            when (val calling = request.callingRequest) {
                is CreatePasswordRequest -> {
                    val target = targetFor(request.callingAppInfo)
                    val serviceName = target.serviceName.ifBlank { getString(R.string.app_name) }
                    val id = repository.save(
                        CredentialDraft(
                            title = serviceName,
                            serviceName = serviceName,
                            website = target.webHost,
                            username = calling.id,
                            password = calling.password,
                            notes = ""
                        ),
                        key
                    )
                    val serviceId = repository.resolveService(serviceName)
                    if (target.webHost.isBlank()) {
                        repository.bindPackage(serviceId, request.callingAppInfo.packageName, UriBinding.SOURCE_AUTOFILL)
                    }
                    if (id > 0L) succeed(CreatePasswordResponse()) else failUnknown()
                }
                is CreatePublicKeyCredentialRequest -> {
                    val origin = WebAuthn.originFor(request.callingAppInfo)
                    val options = try {
                        WebAuthn.parseCreationOptions(calling.requestJson, origin)
                    } catch (e: Exception) {
                        failUnknown()
                        return@launch
                    }
                    val credentialId = com.safevault.app.security.CryptoManager.randomBytes(32)
                    val keyPair = WebAuthn.newKeyPair()
                    repository.savePasskey(
                        PasskeyDraft(
                            serviceName = options.rpName,
                            rpId = options.rpId,
                            credentialId = WebAuthn.base64Url(credentialId),
                            username = options.username,
                            displayName = options.displayName,
                            userHandle = options.userHandle,
                            privateKey = WebAuthn.encodedPrivateKey(keyPair)
                        ),
                        key
                    )
                    val json = WebAuthn.createCredentialJson(
                        options = options,
                        origin = origin,
                        credentialId = credentialId,
                        keyPair = keyPair,
                        clientDataHash = calling.clientDataHash
                    )
                    succeed(CreatePublicKeyCredentialResponse(json))
                }
                else -> failUnsupported()
            }
        }
    }

    private fun targetFor(info: androidx.credentials.provider.CallingAppInfo): Target {
        val origin = WebAuthn.originFor(info)
        val host = WebAuthn.hostFromOrigin(origin)
        return if (host.isNotBlank()) {
            Target(webHost = host, serviceName = UriNormalizer.registrableDomain(host).ifBlank { host })
        } else {
            Target(webHost = "", serviceName = info.packageName.substringAfterLast('.').ifBlank { info.packageName })
        }
    }

    private fun succeed(response: androidx.credentials.CreateCredentialResponse) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(result, response)
        setResult(RESULT_OK, result)
        finish()
    }

    private fun failUnsupported() {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(
            result,
            CreateCredentialUnsupportedException(getString(R.string.credential_provider_unsupported))
        )
        setResult(RESULT_OK, result)
        finish()
    }

    private fun failUnknown() {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(
            result,
            CreateCredentialUnknownException(getString(R.string.credential_provider_failed))
        )
        setResult(RESULT_OK, result)
        finish()
    }

    private data class Target(val webHost: String, val serviceName: String)
}
