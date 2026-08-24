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
}
