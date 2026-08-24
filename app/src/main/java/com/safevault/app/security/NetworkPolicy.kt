package com.safevault.app.security

/**
 * Single boundary for code paths that can leave the device.
 *
 * Phase 6 deliberately starts from DENY_ALL even though the manifest now declares
 * INTERNET. Connected backup has to opt in through this boundary, with a stored
 * consent timestamp and an HTTPS endpoint. Other network capabilities should be
 * added as named cases here before they open a socket.
 */
class NetworkPolicy(private val settings: Settings = Settings()) {

    enum class Mode {
        DENY_ALL,
        CONNECTED_BACKUP_ONLY
    }

    enum class Capability {
        CONNECTED_BACKUP_UPLOAD
    }

    data class Settings(
        val mode: Mode = Mode.DENY_ALL,
        val connectedBackupConsentAt: Long = 0L,
        val connectedBackupEndpoint: String = ""
    )

    data class Decision(
        val allowed: Boolean,
        val reason: String
    )

    fun evaluate(capability: Capability): Decision {
        if (settings.mode == Mode.DENY_ALL) {
            return Decision(false, "Network Lock is on")
        }

        return when (capability) {
            Capability.CONNECTED_BACKUP_UPLOAD -> evaluateConnectedBackup()
        }
    }

    private fun evaluateConnectedBackup(): Decision {
        if (settings.mode != Mode.CONNECTED_BACKUP_ONLY) {
            return Decision(false, "Connected backup is not enabled")
        }
        if (settings.connectedBackupConsentAt <= 0L) {
            return Decision(false, "Connected backup consent has not been recorded")
        }
        if (!isHttpsEndpoint(settings.connectedBackupEndpoint)) {
            return Decision(false, "Connected backup needs an HTTPS endpoint")
        }
        return Decision(true, "Connected backup upload allowed")
    }

    companion object {
        fun isHttpsEndpoint(endpoint: String): Boolean {
            val trimmed = endpoint.trim()
            if (trimmed.isEmpty()) return false
            return try {
                val uri = java.net.URI(trimmed)
                uri.scheme.equals("https", ignoreCase = true) &&
                    !uri.host.isNullOrBlank() &&
                    uri.userInfo == null
            } catch (e: Exception) {
                false
            }
        }
    }
}
