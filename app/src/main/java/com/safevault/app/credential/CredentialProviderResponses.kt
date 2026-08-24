package com.safevault.app.credential

import android.app.PendingIntent
import android.content.Context
import android.graphics.drawable.Icon
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.safevault.app.R
import com.safevault.app.data.CredentialMatch
import com.safevault.app.data.PasskeyCredential
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.SessionManager
import java.time.Instant

object CredentialProviderResponses {
    private const val MAX_ENTRIES = 8

    fun locked(context: Context, requestCode: Int): BeginGetCredentialResponse =
        BeginGetCredentialResponse.Builder()
            .addAuthenticationAction(
                AuthenticationAction(
                    context.getString(R.string.credential_provider_unlock),
                    SafeVaultCredentialAuthActivity.pendingIntent(context, requestCode)
                )
            )
            .build()

    suspend fun unlocked(
        context: Context,
        repository: VaultRepository,
        request: BeginGetCredentialRequest
    ): BeginGetCredentialResponse {
        val builder = BeginGetCredentialResponse.Builder()
        for (option in request.beginGetCredentialOptions) {
            when (option) {
                is BeginGetPasswordOption -> passwordEntries(context, repository, request.callingAppInfo, option)
                    .forEach { builder.addCredentialEntry(it) }
                is BeginGetPublicKeyCredentialOption -> passkeyEntries(context, repository, option)
                    .forEach { builder.addCredentialEntry(it) }
            }
        }
        return builder.build()
    }

    private suspend fun passwordEntries(
        context: Context,
        repository: VaultRepository,
        callingAppInfo: CallingAppInfo?,
        option: BeginGetPasswordOption
    ): List<androidx.credentials.provider.CredentialEntry> {
        val matches = passwordMatches(repository, callingAppInfo).take(MAX_ENTRIES)
        val key = SessionManager.key ?: return emptyList()
        return matches.mapNotNull { match ->
            val detail = try {
                repository.load(match.entry.id, key)
            } catch (e: Exception) {
                null
            } ?: return@mapNotNull null
            PasswordCredentialEntry.Builder(
                context,
                detail.username.ifBlank { context.getString(R.string.autofill_no_username) },
                SafeVaultCredentialGetActivity.pendingIntent(context, "password", match.entry.id),
                option
            )
                .setDisplayName(match.entry.groupLabel)
                .setIcon(Icon.createWithResource(context, R.drawable.ic_key))
                .setLastUsedTime(instant(match.entry.lastUsedAt))
                .build()
        }
    }

    suspend fun passwordMatches(
        repository: VaultRepository,
        callingAppInfo: CallingAppInfo?
    ): List<CredentialMatch> {
        val origin = WebAuthn.originFor(callingAppInfo)
        val host = WebAuthn.hostFromOrigin(origin)
        return if (host.isNotBlank()) {
            repository.matchesForHost(host)
        } else {
            repository.matchesForPackage(callingAppInfo?.packageName.orEmpty())
        }
    }

    private suspend fun passkeyEntries(
        context: Context,
        repository: VaultRepository,
        option: BeginGetPublicKeyCredentialOption
    ): List<androidx.credentials.provider.CredentialEntry> {
        val request = try {
            WebAuthn.parseRequestOptions(option.requestJson)
        } catch (e: Exception) {
            return emptyList()
        }
        if (request.rpId.isBlank()) return emptyList()
        return repository.passkeysForRpId(request.rpId)
            .filter { request.allowedCredentialIds.isEmpty() || it.credentialId in request.allowedCredentialIds }
            .take(MAX_ENTRIES)
            .map { passkeyEntry(context, it, option) }
    }

    private fun passkeyEntry(
        context: Context,
        passkey: PasskeyCredential,
        option: BeginGetPublicKeyCredentialOption
    ): androidx.credentials.provider.CredentialEntry =
        PublicKeyCredentialEntry.Builder(
            context,
            passkey.username.ifBlank { passkey.displayName.ifBlank { passkey.rpId } },
            SafeVaultCredentialGetActivity.pendingIntent(context, "passkey", passkey.id),
            option
        )
            .setDisplayName(passkey.displayName.ifBlank { passkey.rpId })
            .setIcon(Icon.createWithResource(context, R.drawable.ic_key))
            .setLastUsedTime(instant(passkey.lastUsedAt))
            .build()

    private fun instant(value: Long): Instant? =
        value.takeIf { it > 0L }?.let { Instant.ofEpochMilli(it) }
}
