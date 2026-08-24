package com.safevault.app.backup

import android.content.Context
import com.safevault.app.security.NetworkPolicy
import com.safevault.app.security.VaultPrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

class ConnectedBackupManager(
    context: Context,
    uploader: ConnectedBackupUploader = HttpConnectedBackupUploader()
) {

    private val appContext = context.applicationContext
    private val prefs = VaultPrefs(appContext)
    private val localBackups = BackupManager(appContext)
    private val coordinator = ConnectedBackupCoordinator(uploader)

    sealed interface UploadResult {
        data class Success(val entries: Int, val statusCode: Int) : UploadResult
        data class Blocked(val reason: String) : UploadResult
        data class Failed(val reason: String) : UploadResult
    }

    suspend fun uploadNow(
        passphrase: CharArray,
        dek: SecretKey
    ): UploadResult = withContext(Dispatchers.IO) {
        try {
            val settings = prefs.networkPolicySettings()
            val decision = NetworkPolicy(settings).evaluate(NetworkPolicy.Capability.CONNECTED_BACKUP_UPLOAD)
            if (!decision.allowed) {
                return@withContext UploadResult.Blocked(decision.reason)
            }

            val backup = localBackups.createEncryptedPackage(passphrase, dek)
            val verified = BackupPackage.open(backup.bytes, passphrase)?.entries?.size == backup.entryCount
            if (!verified) {
                return@withContext UploadResult.Failed("Generated backup did not verify")
            }

            val request = ConnectedBackupRequest(
                endpoint = settings.connectedBackupEndpoint.trim(),
                fileName = localBackups.suggestedFileName(),
                bytes = backup.bytes
            )

            when (val result = coordinator.upload(request, settings)) {
                is ConnectedBackupCoordinator.Result.Success -> {
                    prefs.lastConnectedBackupAt = System.currentTimeMillis()
                    UploadResult.Success(backup.entryCount, result.statusCode)
                }

                is ConnectedBackupCoordinator.Result.Blocked ->
                    UploadResult.Blocked(result.reason)

                is ConnectedBackupCoordinator.Result.Failed ->
                    UploadResult.Failed(result.reason)
            }
        } catch (e: Exception) {
            UploadResult.Failed(e.message ?: "Connected backup failed")
        }
    }
}
