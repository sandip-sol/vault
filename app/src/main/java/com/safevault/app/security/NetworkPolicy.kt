package com.safevault.app.security

/**
 * Single boundary for code paths that can leave the device.
 *
 * Phase 6 deliberately starts from DENY_ALL even though the manifest now declares
 * INTERNET. Connected backup, sync and breach lookups each have to opt in
 * through this boundary, with a stored consent timestamp and an HTTPS endpoint.
 * New network capabilities should be added as named cases here before they open
 * a socket.
 */
class NetworkPolicy(private val settings: Settings = Settings()) {

    enum class Mode {
        DENY_ALL,
        CONNECTED_BACKUP_ONLY,
        SYNC_AND_SECURITY_INTELLIGENCE
    }

    enum class Capability {
        CONNECTED_BACKUP_UPLOAD,
        SYNC_UPLOAD,
        SYNC_DOWNLOAD,
        BREACH_RANGE_LOOKUP
    }

    data class Settings(
        val mode: Mode = Mode.DENY_ALL,
        val connectedBackupConsentAt: Long = 0L,
        val connectedBackupEndpoint: String = "",
        val syncConsentAt: Long = 0L,
        val syncEndpoint: String = "",
        val breachCheckConsentAt: Long = 0L,
        val breachCheckEndpoint: String = DEFAULT_BREACH_RANGE_ENDPOINT
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
            Capability.SYNC_UPLOAD,
            Capability.SYNC_DOWNLOAD -> evaluateSync()
            Capability.BREACH_RANGE_LOOKUP -> evaluateBreachCheck()
        }
    }

    private fun evaluateConnectedBackup(): Decision {
        if (
            settings.mode != Mode.CONNECTED_BACKUP_ONLY &&
            settings.mode != Mode.SYNC_AND_SECURITY_INTELLIGENCE
        ) {
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

    private fun evaluateSync(): Decision {
        if (settings.mode != Mode.SYNC_AND_SECURITY_INTELLIGENCE) {
            return Decision(false, "Sync is not enabled")
        }
        if (settings.syncConsentAt <= 0L) {
            return Decision(false, "Sync consent has not been recorded")
        }
        if (!isHttpsEndpoint(settings.syncEndpoint)) {
            return Decision(false, "Sync needs an HTTPS endpoint")
        }
        return Decision(true, "Encrypted sync allowed")
    }

    private fun evaluateBreachCheck(): Decision {
        if (settings.mode != Mode.SYNC_AND_SECURITY_INTELLIGENCE) {
            return Decision(false, "Breach checks are not enabled")
        }
        if (settings.breachCheckConsentAt <= 0L) {
            return Decision(false, "Breach-check consent has not been recorded")
        }
        if (!isHttpsEndpoint(settings.breachCheckEndpoint)) {
            return Decision(false, "Breach checks need an HTTPS endpoint")
        }
        return Decision(true, "Breach range lookup allowed")
    }

    companion object {
        const val DEFAULT_BREACH_RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range"

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
