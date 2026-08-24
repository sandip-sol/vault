package com.safevault.app.backup

import com.safevault.app.security.NetworkPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectedBackupCoordinatorTest {

    @Test
    fun `uploader is not called while Network Lock is on`() {
        var calls = 0
        val coordinator = ConnectedBackupCoordinator {
            calls += 1
            ConnectedBackupUploadResult.Success(204)
        }

        val result = coordinator.upload(
            request = request(),
            settings = NetworkPolicy.Settings(mode = NetworkPolicy.Mode.DENY_ALL)
        )

        assertTrue(result is ConnectedBackupCoordinator.Result.Blocked)
        assertEquals(0, calls)
    }

    @Test
    fun `uploader is called only after consent and https endpoint`() {
        var calls = 0
        val coordinator = ConnectedBackupCoordinator {
            calls += 1
            ConnectedBackupUploadResult.Success(201)
        }

        val result = coordinator.upload(
            request = request(),
            settings = NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.CONNECTED_BACKUP_ONLY,
                connectedBackupConsentAt = 42L,
                connectedBackupEndpoint = "https://backup.example/upload"
            )
        )

        assertTrue(result is ConnectedBackupCoordinator.Result.Success)
        assertEquals(1, calls)
    }

    private fun request() = ConnectedBackupRequest(
        endpoint = "https://backup.example/upload",
        fileName = "safevault-test.svbackup",
        bytes = byteArrayOf(1, 2, 3)
    )
}
