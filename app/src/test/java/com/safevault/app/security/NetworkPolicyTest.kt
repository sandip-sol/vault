package com.safevault.app.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkPolicyTest {

    @Test
    fun `default policy denies connected backup`() {
        val decision = NetworkPolicy().evaluate(NetworkPolicy.Capability.CONNECTED_BACKUP_UPLOAD)

        assertFalse(decision.allowed)
    }

    @Test
    fun `deny all wins even with consent and endpoint`() {
        val decision = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.DENY_ALL,
                connectedBackupConsentAt = 42L,
                connectedBackupEndpoint = "https://backup.example/upload"
            )
        ).evaluate(NetworkPolicy.Capability.CONNECTED_BACKUP_UPLOAD)

        assertFalse(decision.allowed)
    }

    @Test
    fun `connected backup requires recorded consent`() {
        val decision = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.CONNECTED_BACKUP_ONLY,
                connectedBackupEndpoint = "https://backup.example/upload"
            )
        ).evaluate(NetworkPolicy.Capability.CONNECTED_BACKUP_UPLOAD)

        assertFalse(decision.allowed)
    }

    @Test
    fun `connected backup requires https endpoint`() {
        val decision = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.CONNECTED_BACKUP_ONLY,
                connectedBackupConsentAt = 42L,
                connectedBackupEndpoint = "http://backup.example/upload"
            )
        ).evaluate(NetworkPolicy.Capability.CONNECTED_BACKUP_UPLOAD)

        assertFalse(decision.allowed)
    }

    @Test
    fun `connected backup allows explicit https upload`() {
        val decision = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.CONNECTED_BACKUP_ONLY,
                connectedBackupConsentAt = 42L,
                connectedBackupEndpoint = "https://backup.example/upload"
            )
        ).evaluate(NetworkPolicy.Capability.CONNECTED_BACKUP_UPLOAD)

        assertTrue(decision.allowed)
    }

    @Test
    fun `sync is denied in connected-backup-only mode`() {
        val decision = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.CONNECTED_BACKUP_ONLY,
                connectedBackupConsentAt = 42L,
                connectedBackupEndpoint = "https://backup.example/upload",
                syncConsentAt = 42L,
                syncEndpoint = "https://sync.example/vault"
            )
        ).evaluate(NetworkPolicy.Capability.SYNC_UPLOAD)

        assertFalse(decision.allowed)
    }

    @Test
    fun `sync requires consent and https endpoint`() {
        val missingConsent = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.SYNC_AND_SECURITY_INTELLIGENCE,
                syncEndpoint = "https://sync.example/vault"
            )
        ).evaluate(NetworkPolicy.Capability.SYNC_UPLOAD)
        val http = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.SYNC_AND_SECURITY_INTELLIGENCE,
                syncConsentAt = 42L,
                syncEndpoint = "http://sync.example/vault"
            )
        ).evaluate(NetworkPolicy.Capability.SYNC_DOWNLOAD)

        assertFalse(missingConsent.allowed)
        assertFalse(http.allowed)
    }

    @Test
    fun `sync allows explicit https upload and download`() {
        val settings = NetworkPolicy.Settings(
            mode = NetworkPolicy.Mode.SYNC_AND_SECURITY_INTELLIGENCE,
            syncConsentAt = 42L,
            syncEndpoint = "https://sync.example/vault"
        )

        assertTrue(NetworkPolicy(settings).evaluate(NetworkPolicy.Capability.SYNC_UPLOAD).allowed)
        assertTrue(NetworkPolicy(settings).evaluate(NetworkPolicy.Capability.SYNC_DOWNLOAD).allowed)
    }

    @Test
    fun `breach lookup requires separate consent`() {
        val decision = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.SYNC_AND_SECURITY_INTELLIGENCE,
                breachCheckEndpoint = NetworkPolicy.DEFAULT_BREACH_RANGE_ENDPOINT
            )
        ).evaluate(NetworkPolicy.Capability.BREACH_RANGE_LOOKUP)

        assertFalse(decision.allowed)
    }

    @Test
    fun `breach lookup allows consented https range endpoint`() {
        val decision = NetworkPolicy(
            NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.SYNC_AND_SECURITY_INTELLIGENCE,
                breachCheckConsentAt = 42L,
                breachCheckEndpoint = NetworkPolicy.DEFAULT_BREACH_RANGE_ENDPOINT
            )
        ).evaluate(NetworkPolicy.Capability.BREACH_RANGE_LOOKUP)

        assertTrue(decision.allowed)
    }
}
