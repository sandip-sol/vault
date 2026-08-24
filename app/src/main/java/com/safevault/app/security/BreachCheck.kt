package com.safevault.app.security

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

data class BreachRangeRequest(
    val endpoint: String,
    val prefix: String
)

sealed interface BreachRangeResult {
    data class Success(val responseBody: String) : BreachRangeResult
    data class Failed(val reason: String) : BreachRangeResult
}

fun interface BreachRangeClient {
    fun lookup(request: BreachRangeRequest): BreachRangeResult
}

object BreachCheck {

    data class HashParts(
        val prefix: String,
        val suffix: String
    )

    fun hashParts(password: String): HashParts {
        val digest = MessageDigest.getInstance("SHA-1")
            .digest(password.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02X".format(it) }
        return HashParts(prefix = digest.take(5), suffix = digest.drop(5))
    }

    fun countForSuffix(rangeBody: String, suffix: String): Int {
        val target = suffix.uppercase()
        return rangeBody
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .firstNotNullOfOrNull { line ->
                val parts = line.split(':', limit = 2)
                val returnedSuffix = parts.getOrNull(0)?.trim()?.uppercase()
                val count = parts.getOrNull(1)?.trim()?.toIntOrNull()
                if (returnedSuffix == target) count else null
            } ?: 0
    }
}

class BreachCheckCoordinator(
    private val client: BreachRangeClient
) {

    sealed interface Result {
        data class Clean(val prefix: String) : Result
        data class Breached(val prefix: String, val count: Int) : Result
        data class Blocked(val reason: String) : Result
        data class Failed(val reason: String) : Result
    }

    fun checkPassword(password: String, settings: NetworkPolicy.Settings): Result {
        val decision = NetworkPolicy(settings).evaluate(NetworkPolicy.Capability.BREACH_RANGE_LOOKUP)
        if (!decision.allowed) return Result.Blocked(decision.reason)

        val parts = BreachCheck.hashParts(password)
        return when (
            val response = client.lookup(
                BreachRangeRequest(endpoint = settings.breachCheckEndpoint.trim(), prefix = parts.prefix)
            )
        ) {
            is BreachRangeResult.Success -> {
                val count = BreachCheck.countForSuffix(response.responseBody, parts.suffix)
                if (count > 0) Result.Breached(parts.prefix, count) else Result.Clean(parts.prefix)
            }

            is BreachRangeResult.Failed -> Result.Failed(response.reason)
        }
    }
}

class HttpBreachRangeClient : BreachRangeClient {

    override fun lookup(request: BreachRangeRequest): BreachRangeResult {
        if (!NetworkPolicy.isHttpsEndpoint(request.endpoint)) {
            return BreachRangeResult.Failed("Breach checks need an HTTPS endpoint")
        }
        if (!request.prefix.matches(Regex("[0-9A-F]{5}"))) {
            return BreachRangeResult.Failed("Invalid breach-check hash prefix")
        }

        val endpoint = request.endpoint.trim().trimEnd('/') + "/" + request.prefix
        val connection = try {
            (URL(endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                setRequestProperty("Add-Padding", "true")
            }
        } catch (e: Exception) {
            return BreachRangeResult.Failed(e.message ?: "Could not open breach-check endpoint")
        }

        return try {
            val status = connection.responseCode
            if (status in 200..299) {
                BreachRangeResult.Success(connection.inputStream.use { stream ->
                    stream.bufferedReader(Charsets.UTF_8).readText()
                })
            } else {
                connection.errorStream?.close()
                BreachRangeResult.Failed("Server returned HTTP $status")
            }
        } catch (e: Exception) {
            BreachRangeResult.Failed(e.message ?: "Breach check failed")
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 15_000
        const val READ_TIMEOUT_MS = 30_000
    }
}
