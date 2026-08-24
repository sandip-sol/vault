package com.safevault.app.sync

import com.safevault.app.security.NetworkPolicy
import java.net.HttpURLConnection
import java.net.URL

data class SyncUploadRequest(
    val endpoint: String,
    val deviceId: String,
    val revision: Long,
    val bytes: ByteArray
)

data class LocalSyncState(
    val deviceId: String,
    val revision: Long,
    val lastSyncedRevision: Long
)

sealed interface SyncTransportResult {
    data class Uploaded(val statusCode: Int) : SyncTransportResult
    data class Downloaded(val bytes: ByteArray) : SyncTransportResult
    data class Failed(val reason: String) : SyncTransportResult
}

interface SyncTransport {
    fun upload(request: SyncUploadRequest): SyncTransportResult
    fun download(endpoint: String): SyncTransportResult
}

object SyncConflictResolver {
    sealed interface Decision {
        data object UploadLocal : Decision
        data object ApplyRemote : Decision
        data object IgnoreRemote : Decision
        data class Conflict(val reason: String) : Decision
    }

    fun decide(local: LocalSyncState, remote: SyncPackage.Header): Decision {
        if (remote.revision <= 0L) return Decision.Conflict("Remote snapshot has no revision")
        if (remote.deviceId == local.deviceId && remote.revision <= local.revision) {
            return Decision.IgnoreRemote
        }
        if (remote.revision <= local.lastSyncedRevision) return Decision.IgnoreRemote
        if (local.revision == local.lastSyncedRevision) return Decision.ApplyRemote
        if (remote.baseRevision == local.revision) return Decision.ApplyRemote
        if (local.revision > remote.revision) return Decision.UploadLocal
        return Decision.Conflict("Both the local vault and remote snapshot changed")
    }
}

class SyncCoordinator(
    private val transport: SyncTransport
) {

    sealed interface Result {
        data class Success(val statusCode: Int) : Result
        data class Downloaded(val bytes: ByteArray) : Result
        data class Blocked(val reason: String) : Result
        data class Failed(val reason: String) : Result
    }

    fun upload(request: SyncUploadRequest, settings: NetworkPolicy.Settings): Result {
        val decision = NetworkPolicy(settings).evaluate(NetworkPolicy.Capability.SYNC_UPLOAD)
        if (!decision.allowed) return Result.Blocked(decision.reason)

        return when (val result = transport.upload(request)) {
            is SyncTransportResult.Uploaded -> Result.Success(result.statusCode)
            is SyncTransportResult.Failed -> Result.Failed(result.reason)
            is SyncTransportResult.Downloaded -> Result.Failed("Sync upload returned a download response")
        }
    }

    fun download(endpoint: String, settings: NetworkPolicy.Settings): Result {
        val decision = NetworkPolicy(settings).evaluate(NetworkPolicy.Capability.SYNC_DOWNLOAD)
        if (!decision.allowed) return Result.Blocked(decision.reason)

        return when (val result = transport.download(endpoint)) {
            is SyncTransportResult.Downloaded -> Result.Downloaded(result.bytes)
            is SyncTransportResult.Failed -> Result.Failed(result.reason)
            is SyncTransportResult.Uploaded -> Result.Failed("Sync download returned an upload response")
        }
    }
}

class HttpSyncTransport : SyncTransport {

    override fun upload(request: SyncUploadRequest): SyncTransportResult {
        if (!NetworkPolicy.isHttpsEndpoint(request.endpoint)) {
            return SyncTransportResult.Failed("Sync needs an HTTPS endpoint")
        }

        val connection = try {
            (URL(request.endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod = "PUT"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", SyncPackage.MIME_TYPE)
                setRequestProperty("X-SafeVault-Device", request.deviceId)
                setRequestProperty("X-SafeVault-Revision", request.revision.toString())
                setFixedLengthStreamingMode(request.bytes.size)
            }
        } catch (e: Exception) {
            return SyncTransportResult.Failed(e.message ?: "Could not open sync endpoint")
        }

        return try {
            connection.outputStream.use { it.write(request.bytes) }
            val status = connection.responseCode
            if (status in 200..299) {
                connection.inputStream?.close()
                SyncTransportResult.Uploaded(status)
            } else {
                connection.errorStream?.close()
                SyncTransportResult.Failed("Server returned HTTP $status")
            }
        } catch (e: Exception) {
            SyncTransportResult.Failed(e.message ?: "Sync upload failed")
        } finally {
            connection.disconnect()
        }
    }

    override fun download(endpoint: String): SyncTransportResult {
        if (!NetworkPolicy.isHttpsEndpoint(endpoint)) {
            return SyncTransportResult.Failed("Sync needs an HTTPS endpoint")
        }

        val connection = try {
            (URL(endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
            }
        } catch (e: Exception) {
            return SyncTransportResult.Failed(e.message ?: "Could not open sync endpoint")
        }

        return try {
            val status = connection.responseCode
            if (status in 200..299) {
                SyncTransportResult.Downloaded(connection.inputStream.use { it.readBytes() })
            } else {
                connection.errorStream?.close()
                SyncTransportResult.Failed("Server returned HTTP $status")
            }
        } catch (e: Exception) {
            SyncTransportResult.Failed(e.message ?: "Sync download failed")
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 15_000
        const val READ_TIMEOUT_MS = 30_000
    }
}
