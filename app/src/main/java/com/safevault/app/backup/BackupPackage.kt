package com.safevault.app.backup

import android.util.Base64
import com.safevault.app.data.UriBinding
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultService
import com.safevault.app.security.CryptoManager
import com.safevault.app.security.KeyDerivation
import org.json.JSONArray
import org.json.JSONObject
import javax.crypto.SecretKey

/**
 * The on-disk encrypted backup format (roadmap §11, "Encrypted export package").
 *
 * The file is a small JSON header wrapping one AEAD blob:
 *
 *     {
 *       "format": "safevault.backup",
 *       "version": 1,
 *       "createdAt": <epoch millis>,
 *       "entryCount": <int>,              // for the restore preview, non-secret
 *       "kdf": { version, algorithm, iterations, salt },
 *       "payload": "v2.<base64 iv||ciphertext||tag>"
 *     }
 *
 * The header is cleartext on purpose: restore has to read the KDF parameters
 * before it can ask for a passphrase, and none of it reveals vault contents. The
 * whole payload — the vault DEK *and* every record — sits under a single GCM tag
 * keyed from the backup passphrase, so a truncated or edited file fails to
 * authenticate as a unit and nothing is imported.
 *
 * The payload carries the DEK rather than plaintext records, which is what lets
 * restore re-wrap one key for the new device instead of re-encrypting the vault.
 * No Android Keystore material is ever exported: those keys are device-bound by
 * design and a new device mints its own.
 */
object BackupPackage {

    const val FORMAT = "safevault.backup"
    /**
     * Bumped to 2 when services and URI bindings became their own tables.
     *
     * v1 files still restore: they simply carry no services, and the entries in
     * them still have their `serviceName` text, so [rebuildServices] reconstructs
     * the service rows the same way the 2 -> 3 database migration does. A backup
     * taken before Phase 3 therefore restores into a Phase 3 vault with grouping
     * intact and no bindings — which is exactly what it knew.
     */
    const val VERSION = 2
    private val READABLE_VERSIONS = setOf(1, 2)
    const val FILE_EXTENSION = "svbak"
    const val MIME_TYPE = "application/octet-stream"

    private const val AAD = "safevault/backup/v1"

    class MalformedBackupException(message: String) : Exception(message)

    /** Header fields readable before the passphrase is known. */
    data class Header(
        val version: Int,
        val createdAt: Long,
        val entryCount: Int,
        val kdf: KeyDerivation.KdfParams
    )

    data class Contents(
        val dek: SecretKey,
        val vaultCreatedAt: Long,
        val entries: List<VaultEntry>,
        val services: List<VaultService>,
        val bindings: List<UriBinding>
    )

    // ── Writing ────────────────────────────────────────────────────────────

    fun write(
        passphrase: CharArray,
        dek: SecretKey,
        vaultCreatedAt: Long,
        entries: List<VaultEntry>,
        services: List<VaultService>,
        bindings: List<UriBinding>
    ): ByteArray {
        val kdf = KeyDerivation.newParams(KeyDerivation.BACKUP_ITERATIONS)
        val kek = KeyDerivation.deriveKek(passphrase, kdf)

        val inner = JSONObject().apply {
            put("dek", Base64.encodeToString(dek.encoded, Base64.NO_WRAP))
            put("vaultCreatedAt", vaultCreatedAt)
            put("entries", JSONArray().apply { entries.forEach { put(toJson(it)) } })
            put("services", JSONArray().apply { services.forEach { put(toJson(it)) } })
            put("bindings", JSONArray().apply { bindings.forEach { put(toJson(it)) } })
        }

        val envelope = JSONObject().apply {
            put("format", FORMAT)
            put("version", VERSION)
            put("createdAt", System.currentTimeMillis())
            put("entryCount", entries.size)
            put("kdf", JSONObject().apply {
                put("version", kdf.version)
                put("algorithm", "PBKDF2WithHmacSHA256")
                put("iterations", kdf.iterations)
                put("salt", Base64.encodeToString(kdf.salt, Base64.NO_WRAP))
            })
            put("payload", CryptoManager.encrypt(inner.toString(), kek, AAD))
        }
        return envelope.toString(2).toByteArray(Charsets.UTF_8)
    }

    // ── Reading ────────────────────────────────────────────────────────────

    fun readHeader(bytes: ByteArray): Header {
        val json = parse(bytes)
        if (json.optString("format") != FORMAT) {
            throw MalformedBackupException("Not a SafeVault backup file")
        }
        val version = json.optInt("version", -1)
        if (version !in READABLE_VERSIONS) {
            throw MalformedBackupException("Unsupported backup version $version")
        }
        val kdfJson = json.optJSONObject("kdf")
            ?: throw MalformedBackupException("Backup is missing its KDF parameters")
        val salt = kdfJson.optString("salt").takeIf { it.isNotEmpty() }
            ?: throw MalformedBackupException("Backup is missing its KDF salt")

        return Header(
            version = version,
            createdAt = json.optLong("createdAt", 0L),
            entryCount = json.optInt("entryCount", 0),
            kdf = KeyDerivation.KdfParams(
                version = kdfJson.optInt("version", KeyDerivation.CURRENT_VERSION),
                iterations = kdfJson.optInt("iterations", KeyDerivation.BACKUP_ITERATIONS),
                salt = Base64.decode(salt, Base64.NO_WRAP)
            )
        )
    }

    /**
     * @return the decrypted contents, or null when the passphrase is wrong — the
     *   GCM tag is the only thing that decides, so a wrong passphrase and a
     *   corrupted file are indistinguishable to an attacker.
     */
    fun open(bytes: ByteArray, passphrase: CharArray): Contents? {
        val header = readHeader(bytes)
        val payload = parse(bytes).optString("payload").takeIf { it.isNotEmpty() }
            ?: throw MalformedBackupException("Backup has no payload")

        val kek = KeyDerivation.deriveKek(passphrase, header.kdf)
        val plain = try {
            CryptoManager.decrypt(payload, kek, AAD)
        } catch (e: Exception) {
            return null
        }

        val inner = try {
            JSONObject(plain)
        } catch (e: Exception) {
            throw MalformedBackupException("Backup payload is not valid JSON")
        }

        val dekBytes = Base64.decode(inner.getString("dek"), Base64.NO_WRAP)
        val array = inner.optJSONArray("entries") ?: JSONArray()
        val entries = (0 until array.length()).map { entryFromJson(array.getJSONObject(it)) }

        if (entries.size != header.entryCount) {
            throw MalformedBackupException(
                "Backup claims ${header.entryCount} entries but carries ${entries.size}"
            )
        }

        val servicesJson = inner.optJSONArray("services") ?: JSONArray()
        val bindingsJson = inner.optJSONArray("bindings") ?: JSONArray()
        var services = (0 until servicesJson.length())
            .map { serviceFromJson(servicesJson.getJSONObject(it)) }
        var bindings = (0 until bindingsJson.length())
            .map { bindingFromJson(bindingsJson.getJSONObject(it)) }
        var restoredEntries = entries

        if (header.version < 2 || services.isEmpty()) {
            // A pre-Phase-3 file, or one whose entries were never grouped. The
            // entry rows still carry `serviceName`, so services are recoverable
            // from them by the same rule the database migration uses.
            val rebuilt = rebuildServices(entries)
            restoredEntries = rebuilt.first
            services = rebuilt.second
            bindings = emptyList()
        }

        // A binding whose service did not survive can only match nothing, and
        // would violate the foreign key on insert.
        val serviceIds = services.map { it.id }.toSet()
        bindings = bindings.filter { it.serviceId in serviceIds }

        return Contents(
            dek = CryptoManager.keyFromBytes(dekBytes),
            vaultCreatedAt = inner.optLong("vaultCreatedAt", 0L),
            entries = restoredEntries,
            services = services,
            bindings = bindings
        )
    }

    /**
     * Reconstructs service rows from the denormalised `serviceName` on each
     * entry, mirroring the SQL in the 2 -> 3 migration: an entry with no service
     * is filed under its own title, which is already what the list shows it as.
     *
     * @return the entries with `serviceId` filled in, and the services they name.
     */
    private fun rebuildServices(
        entries: List<VaultEntry>
    ): Pair<List<VaultEntry>, List<VaultService>> {
        val now = System.currentTimeMillis()
        val idsByName = linkedMapOf<String, Long>()
        val named = entries.map { entry ->
            val name = entry.serviceName.ifBlank { entry.title }.trim()
            if (name.isEmpty()) return@map entry.copy(serviceId = 0L, serviceName = "")
            val id = idsByName.getOrPut(name.lowercase()) { (idsByName.size + 1).toLong() }
            entry.copy(serviceId = id, serviceName = name)
        }
        val names = named.filter { it.serviceId > 0 }
            .associateBy({ it.serviceId }, { it.serviceName })
        val services = idsByName.values.map { id ->
            VaultService(id = id, name = names[id].orEmpty(), createdAt = now, updatedAt = now)
        }
        return named to services
    }

    // ── Row mapping ────────────────────────────────────────────────────────

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
        throw MalformedBackupException("File is not a readable backup")
    }
}
