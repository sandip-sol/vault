package com.safevault.app.backup

import com.safevault.app.security.NetworkPolicy
import java.net.HttpURLConnection
import java.net.URL

data class ConnectedBackupRequest(
    val endpoint: String,
    val fileName: String,
    val bytes: ByteArray
)

sealed interface ConnectedBackupUploadResult {
    data class Success(val statusCode: Int) : ConnectedBackupUploadResult
    data class Failed(val reason: String) : ConnectedBackupUploadResult
}

fun interface ConnectedBackupUploader {
    fun upload(request: ConnectedBackupRequest): ConnectedBackupUploadResult
}

class ConnectedBackupCoordinator(
    private val uploader: ConnectedBackupUploader
) {

    sealed interface Result {
        data class Success(val statusCode: Int) : Result
        data class Blocked(val reason: String) : Result
        data class Failed(val reason: String) : Result
    }

    fun upload(
        request: ConnectedBackupRequest,
        settings: NetworkPolicy.Settings
    ): Result {
        val decision = NetworkPolicy(settings).evaluate(NetworkPolicy.Capability.CONNECTED_BACKUP_UPLOAD)
        if (!decision.allowed) return Result.Blocked(decision.reason)

        return when (val result = uploader.upload(request)) {
            is ConnectedBackupUploadResult.Success -> Result.Success(result.statusCode)
            is ConnectedBackupUploadResult.Failed -> Result.Failed(result.reason)
        }
    }
}

class HttpConnectedBackupUploader : ConnectedBackupUploader {

    override fun upload(request: ConnectedBackupRequest): ConnectedBackupUploadResult {
        if (!NetworkPolicy.isHttpsEndpoint(request.endpoint)) {
            return ConnectedBackupUploadResult.Failed("Connected backup needs an HTTPS endpoint")
        }

        val connection = try {
            (URL(request.endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", BackupPackage.MIME_TYPE)
                setRequestProperty("X-SafeVault-Filename", request.fileName)
                setFixedLengthStreamingMode(request.bytes.size)
            }
        } catch (e: Exception) {
            return ConnectedBackupUploadResult.Failed(e.message ?: "Could not open backup endpoint")
        }

        return try {
            connection.outputStream.use { it.write(request.bytes) }
            val status = connection.responseCode
            if (status in 200..299) {
                connection.inputStream?.close()
                ConnectedBackupUploadResult.Success(status)
            } else {
                connection.errorStream?.close()
                ConnectedBackupUploadResult.Failed("Server returned HTTP $status")
            }
        } catch (e: Exception) {
            ConnectedBackupUploadResult.Failed(e.message ?: "Connected backup upload failed")
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 15_000
        const val READ_TIMEOUT_MS = 30_000
    }
}
