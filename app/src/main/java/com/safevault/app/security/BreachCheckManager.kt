package com.safevault.app.security

import android.content.Context
import com.safevault.app.data.VaultRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

class BreachCheckManager(
    context: Context,
    client: BreachRangeClient = HttpBreachRangeClient()
) {

    private val appContext = context.applicationContext
    private val repository = VaultRepository(appContext)
    private val prefs = VaultPrefs(appContext)
    private val coordinator = BreachCheckCoordinator(client)

    sealed interface Result {
        data class Success(val checked: Int, val breached: Int) : Result
        data class Blocked(val reason: String) : Result
        data class Failed(val reason: String) : Result
    }

    suspend fun checkVault(dek: SecretKey): Result = withContext(Dispatchers.IO) {
        val settings = prefs.networkPolicySettings()
        var checked = 0
        var breached = 0

        try {
            for (entry in repository.getAll()) {
                val detail = repository.load(entry.id, dek) ?: continue
                when (val result = coordinator.checkPassword(detail.password, settings)) {
                    is BreachCheckCoordinator.Result.Clean -> checked += 1
                    is BreachCheckCoordinator.Result.Breached -> {
                        checked += 1
                        breached += 1
                    }
                    is BreachCheckCoordinator.Result.Blocked -> return@withContext Result.Blocked(result.reason)
                    is BreachCheckCoordinator.Result.Failed -> return@withContext Result.Failed(result.reason)
                }
            }
            prefs.lastBreachCheckAt = System.currentTimeMillis()
            Result.Success(checked, breached)
        } catch (e: Exception) {
            Result.Failed(e.message ?: "Breach check failed")
        }
    }
}
