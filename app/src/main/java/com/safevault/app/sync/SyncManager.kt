package com.safevault.app.sync

import android.content.Context
import com.safevault.app.data.ServiceBackfill
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.VaultPrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

class SyncManager(
    context: Context,
    transport: SyncTransport = HttpSyncTransport()
) {

    private val appContext = context.applicationContext
    private val repository = VaultRepository(appContext)
    private val prefs = VaultPrefs(appContext)
    private val coordinator = SyncCoordinator(transport)

    sealed interface SyncResult {
        data class Uploaded(val revision: Long, val statusCode: Int) : SyncResult
        data class AppliedRemote(val revision: Long, val entries: Int) : SyncResult
        data object AlreadyCurrent : SyncResult
        data class Conflict(val reason: String) : SyncResult
        data class Blocked(val reason: String) : SyncResult
        data class Failed(val reason: String) : SyncResult
    }

    suspend fun uploadNow(dek: SecretKey): SyncResult = withContext(Dispatchers.IO) {
        try {
            val settings = prefs.networkPolicySettings()
            val localRevision = maxOf(repository.localRevision(), prefs.syncLastRevision)
            val revision = maxOf(System.currentTimeMillis(), localRevision + 1)
            val bytes = createSnapshot(dek, revision)
            val request = SyncUploadRequest(
                endpoint = settings.syncEndpoint.trim(),
                deviceId = prefs.syncDeviceId,
                revision = revision,
                bytes = bytes
            )

            when (val result = coordinator.upload(request, settings)) {
                is SyncCoordinator.Result.Success -> {
                    prefs.syncLastRevision = revision
                    prefs.lastSyncAt = System.currentTimeMillis()
                    SyncResult.Uploaded(revision, result.statusCode)
                }

                is SyncCoordinator.Result.Blocked -> SyncResult.Blocked(result.reason)
                is SyncCoordinator.Result.Failed -> SyncResult.Failed(result.reason)
                is SyncCoordinator.Result.Downloaded ->
                    SyncResult.Failed("Sync upload returned a download response")
            }
        } catch (e: Exception) {
            SyncResult.Failed(e.message ?: "Sync upload failed")
        }
    }

    suspend fun downloadAndApply(dek: SecretKey): SyncResult = withContext(Dispatchers.IO) {
        try {
            val settings = prefs.networkPolicySettings()
            val downloaded = when (val result = coordinator.download(settings.syncEndpoint.trim(), settings)) {
                is SyncCoordinator.Result.Downloaded -> result.bytes
                is SyncCoordinator.Result.Blocked -> return@withContext SyncResult.Blocked(result.reason)
                is SyncCoordinator.Result.Failed -> return@withContext SyncResult.Failed(result.reason)
                is SyncCoordinator.Result.Success ->
                    return@withContext SyncResult.Failed("Sync download returned an upload response")
            }
            val header = SyncPackage.readHeader(downloaded)
            val localRevision = maxOf(repository.localRevision(), prefs.syncLastRevision)
            when (
                val decision = SyncConflictResolver.decide(
                    local = LocalSyncState(
                        deviceId = prefs.syncDeviceId,
                        revision = localRevision,
                        lastSyncedRevision = prefs.syncLastRevision
                    ),
                    remote = header
                )
            ) {
                SyncConflictResolver.Decision.ApplyRemote -> applyRemote(downloaded, dek, header.revision)
                SyncConflictResolver.Decision.IgnoreRemote -> SyncResult.AlreadyCurrent
                SyncConflictResolver.Decision.UploadLocal -> uploadNow(dek)
                is SyncConflictResolver.Decision.Conflict -> SyncResult.Conflict(decision.reason)
            }
        } catch (e: SyncPackage.MalformedSyncException) {
            SyncResult.Failed(e.message ?: "Sync snapshot is not readable")
        } catch (e: Exception) {
            SyncResult.Failed(e.message ?: "Sync download failed")
        }
    }

    private suspend fun createSnapshot(dek: SecretKey, revision: Long): ByteArray =
        SyncPackage.write(
            dek = dek,
            deviceId = prefs.syncDeviceId,
            baseRevision = prefs.syncLastRevision,
            revision = revision,
            vaultCreatedAt = prefs.vaultCreatedAt,
            entries = repository.getAll(),
            services = repository.allServices(),
            bindings = repository.allBindings(),
            passkeys = repository.allPasskeys()
        )

    private suspend fun applyRemote(
        bytes: ByteArray,
        dek: SecretKey,
        revision: Long
    ): SyncResult {
        val contents = SyncPackage.open(bytes, dek)
            ?: return SyncResult.Failed("Sync snapshot could not be decrypted")

        repository.replaceVault(
            entries = contents.entries,
            services = contents.services,
            bindings = contents.bindings,
            passkeys = contents.passkeys
        )
        ServiceBackfill.reset(appContext)
        ServiceBackfill.runIfNeeded(appContext)
        prefs.syncLastRevision = revision
        prefs.lastSyncAt = System.currentTimeMillis()
        return SyncResult.AppliedRemote(revision, contents.entries.size)
    }
}
