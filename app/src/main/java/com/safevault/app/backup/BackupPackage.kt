package com.safevault.app.backup

import android.util.Base64
import com.safevault.app.data.VaultEntry
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
    const val VERSION = 1
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

    data class Contents(val dek: SecretKey, val vaultCreatedAt: Long, val entries: List<VaultEntry>)

    // ── Writing ────────────────────────────────────────────────────────────

    fun write(
        passphrase: CharArray,
        dek: SecretKey,
        vaultCreatedAt: Long,
        entries: List<VaultEntry>
    ): ByteArray {
        val kdf = KeyDerivation.newParams(KeyDerivation.BACKUP_ITERATIONS)
        val kek = KeyDerivation.deriveKek(passphrase, kdf)

        val inner = JSONObject().apply {
            put("dek", Base64.encodeToString(dek.encoded, Base64.NO_WRAP))
            put("vaultCreatedAt", vaultCreatedAt)
            put("entries", JSONArray().apply { entries.forEach { put(toJson(it)) } })
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
        if (version != VERSION) {
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
        val entries = (0 until array.length()).map { fromJson(array.getJSONObject(it)) }

        if (entries.size != header.entryCount) {
            throw MalformedBackupException(
                "Backup claims ${header.entryCount} entries but carries ${entries.size}"
            )
        }
        return Contents(
            dek = CryptoManager.keyFromBytes(dekBytes),
            vaultCreatedAt = inner.optLong("vaultCreatedAt", 0L),
            entries = entries
        )
    }

    // ── Row mapping ────────────────────────────────────────────────────────

    private fun toJson(e: VaultEntry) = JSONObject().apply {
        put("id", e.id)
        put("title", e.title)
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

    private fun fromJson(o: JSONObject) = VaultEntry(
        id = o.optLong("id", 0L),
        title = o.optString("title"),
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
