package com.safevault.app.credential

import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import com.safevault.app.R
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class SafeVaultCredentialProviderService : CredentialProviderService() {

    private val job = Job()
    private val scope = CoroutineScope(SupervisorJob(job))
    private val repository by lazy { VaultRepository(this) }
    private val prefs by lazy { VaultPrefs(this) }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        if (!SessionManager.isUnlockedWithin(prefs.autoLockMs)) {
            callback.onResult(CredentialProviderResponses.locked(this, request.hashCode()))
            return
        }

        val work = scope.launch {
            val response = CredentialProviderResponses.unlocked(this@SafeVaultCredentialProviderService, repository, request)
            if (!cancellationSignal.isCanceled) callback.onResult(response)
        }
        cancellationSignal.setOnCancelListener { work.cancel() }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        if (request is BeginCreatePasswordCredentialRequest ||
            request is androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
        ) {
            val entry = CreateEntry(
                getString(R.string.app_name),
                SafeVaultCredentialCreateActivity.pendingIntent(this, request.hashCode()),
                getString(R.string.credential_provider_save_here),
                null,
                android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_key),
                null,
                null,
                null,
                false
            )
            callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
        } else {
            callback.onError(CreateCredentialUnsupportedException(getString(R.string.credential_provider_unsupported)))
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        callback.onResult(null)
    }
}
