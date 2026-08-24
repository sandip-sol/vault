package com.safevault.app.sync

import com.safevault.app.security.NetworkPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SyncCoordinatorTest {

    @Test
    fun `upload transport is not called while Network Lock is on`() {
        var calls = 0
        val coordinator = SyncCoordinator(object : SyncTransport {
            override fun upload(request: SyncUploadRequest): SyncTransportResult {
                calls += 1
                return SyncTransportResult.Uploaded(204)
            }

            override fun download(endpoint: String): SyncTransportResult {
                calls += 1
                return SyncTransportResult.Downloaded(byteArrayOf())
            }
        })

        val result = coordinator.upload(
            request = request(),
            settings = NetworkPolicy.Settings(mode = NetworkPolicy.Mode.DENY_ALL)
        )

        assertTrue(result is SyncCoordinator.Result.Blocked)
        assertEquals(0, calls)
    }

    @Test
    fun `download transport is called only after sync consent and https endpoint`() {
        var calls = 0
        val coordinator = SyncCoordinator(object : SyncTransport {
            override fun upload(request: SyncUploadRequest): SyncTransportResult =
                SyncTransportResult.Uploaded(204)

            override fun download(endpoint: String): SyncTransportResult {
                calls += 1
                return SyncTransportResult.Downloaded(byteArrayOf(1, 2, 3))
            }
        })

        val result = coordinator.download(
            endpoint = "https://sync.example/vault",
            settings = syncSettings()
        )

        assertTrue(result is SyncCoordinator.Result.Downloaded)
        assertEquals(1, calls)
    }

    @Test
    fun `resolver applies remote when local has no unsynced change`() {
        val decision = SyncConflictResolver.decide(
            local = LocalSyncState(deviceId = "device-a", revision = 10, lastSyncedRevision = 10),
            remote = header(deviceId = "device-b", baseRevision = 10, revision = 11)
        )

        assertTrue(decision is SyncConflictResolver.Decision.ApplyRemote)
    }

    @Test
    fun `resolver reports conflict when both sides changed after last sync`() {
        val decision = SyncConflictResolver.decide(
            local = LocalSyncState(deviceId = "device-a", revision = 12, lastSyncedRevision = 10),
            remote = header(deviceId = "device-b", baseRevision = 10, revision = 13)
        )

        assertTrue(decision is SyncConflictResolver.Decision.Conflict)
    }

    private fun request() = SyncUploadRequest(
        endpoint = "https://sync.example/vault",
        deviceId = "device-a",
        revision = 1,
        bytes = byteArrayOf(1)
    )

    private fun syncSettings() = NetworkPolicy.Settings(
        mode = NetworkPolicy.Mode.SYNC_AND_SECURITY_INTELLIGENCE,
        syncConsentAt = 42L,
        syncEndpoint = "https://sync.example/vault"
    )

    private fun header(deviceId: String, baseRevision: Long, revision: Long) =
        SyncPackage.Header(
            version = SyncPackage.VERSION,
            createdAt = 1L,
            deviceId = deviceId,
            baseRevision = baseRevision,
            revision = revision
        )
}
