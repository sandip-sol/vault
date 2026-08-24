package com.safevault.app.sync

import com.safevault.app.data.PasskeyCredential
import com.safevault.app.data.UriBinding
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultService
import com.safevault.app.security.CryptoManager
import org.json.JSONArray
import org.json.JSONObject
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * End-to-end encrypted sync snapshot.
 *
 * Sync deliberately reuses the existing ciphertext rows rather than decrypting
 * and re-encrypting every credential. The extra sync envelope matters because
 * service names, websites and timestamps are useful app metadata but still vault
 * content: the server only gets routing fields and one AEAD payload.
 */
object SyncPackage {

    const val FORMAT = "safevault.sync"
    const val VERSION = 1
    const val MIME_TYPE = "application/octet-stream"

    private const val AAD = "safevault/sync/v1"
    private const val SYNC_KEY_INFO = "safevault sync snapshot v1"

    class MalformedSyncException(message: String) : Exception(message)

    data class Header(
        val version: Int,
        val createdAt: Long,
        val deviceId: String,
        val baseRevision: Long,
        val revision: Long
    )

    data class Contents(
        val vaultCreatedAt: Long,
        val entries: List<VaultEntry>,
        val services: List<VaultService>,
        val bindings: List<UriBinding>,
        val passkeys: List<PasskeyCredential>
    )

    fun write(
        dek: SecretKey,
        deviceId: String,
        baseRevision: Long,
        revision: Long,
        vaultCreatedAt: Long,
        entries: List<VaultEntry>,
        services: List<VaultService>,
        bindings: List<UriBinding>,
        passkeys: List<PasskeyCredential> = emptyList()
    ): ByteArray {
        require(deviceId.isNotBlank()) { "Sync device id is required" }
        require(revision > 0L) { "Sync revision must be positive" }

        val inner = JSONObject().apply {
            put("vaultCreatedAt", vaultCreatedAt)
            put("entries", JSONArray().apply { entries.forEach { put(toJson(it)) } })
            put("services", JSONArray().apply { services.forEach { put(toJson(it)) } })
            put("bindings", JSONArray().apply { bindings.forEach { put(toJson(it)) } })
            put("passkeys", JSONArray().apply { passkeys.forEach { put(toJson(it)) } })
        }

        val envelope = JSONObject().apply {
            put("format", FORMAT)
            put("version", VERSION)
            put("createdAt", System.currentTimeMillis())
            put("deviceId", deviceId)
            put("baseRevision", baseRevision)
            put("revision", revision)
            put("payload", CryptoManager.encrypt(inner.toString(), syncKey(dek), AAD))
        }
        return envelope.toString(2).toByteArray(Charsets.UTF_8)
    }

    fun readHeader(bytes: ByteArray): Header {
        val json = parse(bytes)
        if (json.optString("format") != FORMAT) {
            throw MalformedSyncException("Not a SafeVault sync snapshot")
        }
        val version = json.optInt("version", -1)
        if (version != VERSION) {
            throw MalformedSyncException("Unsupported sync version $version")
        }

        return Header(
            version = version,
            createdAt = json.optLong("createdAt", 0L),
            deviceId = json.optString("deviceId"),
            baseRevision = json.optLong("baseRevision", 0L),
            revision = json.optLong("revision", 0L)
        )
    }

    fun open(bytes: ByteArray, dek: SecretKey): Contents? {
        readHeader(bytes)
        val payload = parse(bytes).optString("payload").takeIf { it.isNotEmpty() }
            ?: throw MalformedSyncException("Sync snapshot has no payload")
        val plain = try {
            CryptoManager.decrypt(payload, syncKey(dek), AAD)
        } catch (e: Exception) {
            return null
        }
        val inner = try {
            JSONObject(plain)
        } catch (e: Exception) {
            throw MalformedSyncException("Sync payload is not valid JSON")
        }

        val entriesJson = inner.optJSONArray("entries") ?: JSONArray()
        val servicesJson = inner.optJSONArray("services") ?: JSONArray()
        val bindingsJson = inner.optJSONArray("bindings") ?: JSONArray()
        val passkeysJson = inner.optJSONArray("passkeys") ?: JSONArray()

        val entries = (0 until entriesJson.length())
            .map { entryFromJson(entriesJson.getJSONObject(it)) }
        val services = (0 until servicesJson.length())
            .map { serviceFromJson(servicesJson.getJSONObject(it)) }
        val serviceIds = services.map { it.id }.toSet()
        val bindings = (0 until bindingsJson.length())
            .map { bindingFromJson(bindingsJson.getJSONObject(it)) }
            .filter { it.serviceId in serviceIds }
        val passkeys = (0 until passkeysJson.length())
            .map { passkeyFromJson(passkeysJson.getJSONObject(it)) }
            .filter { it.serviceId in serviceIds }

        return Contents(
            vaultCreatedAt = inner.optLong("vaultCreatedAt", 0L),
            entries = entries,
            services = services,
            bindings = bindings,
            passkeys = passkeys
        )
    }

    private fun syncKey(dek: SecretKey): SecretKey {
        val bytes = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(dek.encoded, "HmacSHA256"))
            doFinal(SYNC_KEY_INFO.toByteArray(Charsets.UTF_8))
        }
        return CryptoManager.keyFromBytes(bytes)
    }

    private fun toJson(e: VaultEntry) = JSONObject().apply {
        put("id", e.id)
        put("title", e.title)
        put("serviceId", e.serviceId)
        put("serviceName", e.serviceName)
        put("website", e.website)
        put("username", e.encryptedUsername)
        put("password", e.encryptedPassword)
        put("notes", e.encryptedNotes)
        put("favorite", e.favorite)
        put("reuseHash", e.reuseHash)
        put("strengthScore", e.strengthScore)
        put("passwordUpdatedAt", e.passwordUpdatedAt)
        put("createdAt", e.createdAt)
        put("updatedAt", e.updatedAt)
        put("lastUsedAt", e.lastUsedAt)
        put("payloadSchema", e.payloadSchema)
    }

    private fun toJson(s: VaultService) = JSONObject().apply {
        put("id", s.id)
        put("name", s.name)
        put("createdAt", s.createdAt)
        put("updatedAt", s.updatedAt)
    }

    private fun toJson(b: UriBinding) = JSONObject().apply {
        put("id", b.id)
        put("serviceId", b.serviceId)
        put("kind", b.kind)
        put("value", b.value)
        put("source", b.source)
        put("createdAt", b.createdAt)
    }

    private fun toJson(p: PasskeyCredential) = JSONObject().apply {
        put("id", p.id)
        put("serviceId", p.serviceId)
        put("rpId", p.rpId)
        put("credentialId", p.credentialId)
        put("username", p.username)
        put("displayName", p.displayName)
        put("userHandle", p.encryptedUserHandle)
        put("privateKey", p.encryptedPrivateKey)
        put("signCount", p.signCount)
        put("createdAt", p.createdAt)
        put("updatedAt", p.updatedAt)
        put("lastUsedAt", p.lastUsedAt)
        put("payloadSchema", p.payloadSchema)
    }

    private fun serviceFromJson(o: JSONObject) = VaultService(
        id = o.optLong("id", 0L),
        name = o.optString("name"),
        createdAt = o.optLong("createdAt", 0L),
        updatedAt = o.optLong("updatedAt", 0L)
    )

    private fun bindingFromJson(o: JSONObject) = UriBinding(
        id = o.optLong("id", 0L),
        serviceId = o.optLong("serviceId", 0L),
        kind = o.optInt("kind", UriBinding.KIND_WEB),
        value = o.optString("value"),
        source = o.optInt("source", UriBinding.SOURCE_MANUAL),
        createdAt = o.optLong("createdAt", 0L)
    )

    private fun passkeyFromJson(o: JSONObject) = PasskeyCredential(
        id = o.optLong("id", 0L),
        serviceId = o.optLong("serviceId", 0L),
        rpId = o.optString("rpId"),
        credentialId = o.optString("credentialId"),
        username = o.optString("username"),
        displayName = o.optString("displayName"),
        encryptedUserHandle = o.optString("userHandle"),
        encryptedPrivateKey = o.optString("privateKey"),
        signCount = o.optLong("signCount", 0L),
        createdAt = o.optLong("createdAt", 0L),
        updatedAt = o.optLong("updatedAt", 0L),
        lastUsedAt = o.optLong("lastUsedAt", 0L),
        payloadSchema = o.optInt("payloadSchema", CryptoManager.SCHEMA_CURRENT)
    )

    private fun entryFromJson(o: JSONObject) = VaultEntry(
        id = o.optLong("id", 0L),
        title = o.optString("title"),
        serviceId = o.optLong("serviceId", 0L),
        serviceName = o.optString("serviceName"),
        website = o.optString("website"),
        encryptedUsername = o.optString("username"),
        encryptedPassword = o.optString("password"),
        encryptedNotes = o.optString("notes"),
        notes = "",
        favorite = o.optBoolean("favorite", false),
        reuseHash = o.optString("reuseHash"),
        strengthScore = o.optInt("strengthScore", 0),
        passwordUpdatedAt = o.optLong("passwordUpdatedAt", 0L),
        createdAt = o.optLong("createdAt", 0L),
        updatedAt = o.optLong("updatedAt", 0L),
        lastUsedAt = o.optLong("lastUsedAt", 0L),
        payloadSchema = o.optInt("payloadSchema", CryptoManager.SCHEMA_CURRENT)
    )

    private fun parse(bytes: ByteArray): JSONObject = try {
        JSONObject(String(bytes, Charsets.UTF_8))
    } catch (e: Exception) {
        throw MalformedSyncException("File is not a readable sync snapshot")
    }
}
