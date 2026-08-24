package com.safevault.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BreachCheckTest {

    @Test
    fun `hash parts use five character k anonymity prefix`() {
        val parts = BreachCheck.hashParts("password")

        assertEquals("5BAA6", parts.prefix)
        assertEquals("1E4C9B93F3F0682250B6CF8331B7EE68FD8", parts.suffix)
    }

    @Test
    fun `range response finds matching suffix count`() {
        val count = BreachCheck.countForSuffix(
            rangeBody = """
                00000000000000000000000000000000000:1
                1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003
            """.trimIndent(),
            suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        )

        assertEquals(3_303_003, count)
    }

    @Test
    fun `client is not called while Network Lock is on`() {
        var calls = 0
        val coordinator = BreachCheckCoordinator {
            calls += 1
            BreachRangeResult.Success("")
        }

        val result = coordinator.checkPassword(
            password = "password",
            settings = NetworkPolicy.Settings(mode = NetworkPolicy.Mode.DENY_ALL)
        )

        assertTrue(result is BreachCheckCoordinator.Result.Blocked)
        assertEquals(0, calls)
    }

    @Test
    fun `coordinator sends only hash prefix to range client`() {
        var request: BreachRangeRequest? = null
        val coordinator = BreachCheckCoordinator {
            request = it
            BreachRangeResult.Success("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9")
        }

        val result = coordinator.checkPassword(
            password = "password",
            settings = NetworkPolicy.Settings(
                mode = NetworkPolicy.Mode.SYNC_AND_SECURITY_INTELLIGENCE,
                breachCheckConsentAt = 42L,
                breachCheckEndpoint = NetworkPolicy.DEFAULT_BREACH_RANGE_ENDPOINT
            )
        )

        assertTrue(result is BreachCheckCoordinator.Result.Breached)
        assertEquals("5BAA6", request?.prefix)
        assertTrue(request?.prefix?.contains("password")?.not() == true)
        assertTrue(request?.prefix?.contains("1E4C9B93F3F0682250B6CF8331B7EE68FD8")?.not() == true)
    }
}
