package com.safevault.app.credential

import android.os.Build
import android.util.Base64
import androidx.credentials.provider.CallingAppInfo
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec

object WebAuthn {
    private const val ALG_ES256 = -7
    private const val FLAGS_CREATE = 0x01 or 0x04 or 0x40
    private const val FLAGS_GET = 0x01 or 0x04

    data class CreationOptions(
        val rpId: String,
        val rpName: String,
        val userHandle: String,
        val username: String,
        val displayName: String,
        val challenge: String
    )

    data class RequestOptions(
        val rpId: String,
        val challenge: String,
        val allowedCredentialIds: Set<String>
    )

    fun parseCreationOptions(requestJson: String, origin: String): CreationOptions {
        val json = publicKey(JSONObject(requestJson))
        val rp = json.optJSONObject("rp") ?: JSONObject()
        val user = json.optJSONObject("user") ?: JSONObject()
        val rpId = rp.optString("id").ifBlank { hostFromOrigin(origin) }
        require(rpId.isNotBlank()) { "Passkey request has no RP ID" }
        return CreationOptions(
            rpId = rpId.lowercase(),
            rpName = rp.optString("name").ifBlank { rpId },
            userHandle = user.optString("id").ifBlank { randomId(32) },
            username = user.optString("name").ifBlank { user.optString("displayName") },
            displayName = user.optString("displayName"),
            challenge = json.optString("challenge")
        )
    }

    fun parseRequestOptions(requestJson: String): RequestOptions {
        val json = publicKey(JSONObject(requestJson))
        val allowed = json.optJSONArray("allowCredentials")
            ?.let { array ->
                (0 until array.length()).mapNotNull { index ->
                    array.optJSONObject(index)?.optString("id")?.takeIf { it.isNotBlank() }
                }.toSet()
            }
            ?: emptySet()
        return RequestOptions(
            rpId = json.optString("rpId").lowercase(),
            challenge = json.optString("challenge"),
            allowedCredentialIds = allowed
        )
    }

    fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    fun privateKeyFromBase64Url(value: String): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(base64UrlDecode(value)))

    fun encodedPrivateKey(keyPair: KeyPair): String = base64Url(keyPair.private.encoded)

    fun createCredentialJson(
        options: CreationOptions,
        origin: String,
        credentialId: ByteArray,
        keyPair: KeyPair,
        clientDataHash: ByteArray?
    ): String {
        val clientData = clientDataJson("webauthn.create", options.challenge, origin)
        val attestationObject = Cbor.map(
            Cbor.text("fmt") to Cbor.text("none"),
            Cbor.text("attStmt") to Cbor.map(),
            Cbor.text("authData") to Cbor.bytes(
                authenticatorData(
                    rpId = options.rpId,
                    flags = FLAGS_CREATE,
                    signCount = 0,
                    attestedCredentialData = attestedCredentialData(credentialId, keyPair.public as ECPublicKey)
                )
            )
        )
        return JSONObject().apply {
            put("id", base64Url(credentialId))
            put("rawId", base64Url(credentialId))
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("clientExtensionResults", JSONObject())
            put("response", JSONObject().apply {
                put("clientDataJSON", base64Url(clientData.toByteArray(Charsets.UTF_8)))
                put("attestationObject", base64Url(attestationObject))
                // Keep a deterministic signature base for providers that supply
                // clientDataHash, even though none-format attestation signs nothing.
                clientDataHash?.let { put("clientDataHash", base64Url(it)) }
            })
        }.toString()
    }

    fun getCredentialJson(
        options: RequestOptions,
        origin: String,
        packageName: String,
        credentialId: String,
        userHandle: String,
        privateKey: PrivateKey,
        signCount: Long,
        clientDataHash: ByteArray?
    ): String {
        val clientData = clientDataJson("webauthn.get", options.challenge, origin)
        val clientDataBytes = clientData.toByteArray(Charsets.UTF_8)
        val effectiveHash = clientDataHash?.takeIf { it.isNotEmpty() } ?: sha256(clientDataBytes)
        val authData = authenticatorData(options.rpId, FLAGS_GET, signCount.coerceAtLeast(0), null)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(authData + effectiveHash)
            sign()
        }
        return JSONObject().apply {
            put("id", credentialId)
            put("rawId", credentialId)
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("clientExtensionResults", JSONObject())
            put("response", JSONObject().apply {
                put("clientDataJSON", base64Url(clientDataBytes))
                put("authenticatorData", base64Url(authData))
                put("signature", base64Url(signature))
                put("userHandle", userHandle)
            })
            if (packageName.isNotBlank()) put("androidPackageName", packageName)
        }.toString()
    }

    fun originFor(info: CallingAppInfo?): String {
        val origin = info?.origin.orEmpty()
        if (origin.isNotBlank()) return origin
        return androidOrigin(info) ?: ""
    }

    fun hostFromOrigin(origin: String): String {
        if (!origin.startsWith("https://") && !origin.startsWith("http://")) return ""
        return com.safevault.app.autofill.UriNormalizer.normalizeHost(origin)
    }

    fun base64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun base64UrlDecode(value: String): ByteArray =
        Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun randomId(size: Int): String = base64Url(com.safevault.app.security.CryptoManager.randomBytes(size))

    private fun publicKey(json: JSONObject): JSONObject = json.optJSONObject("publicKey") ?: json

    private fun clientDataJson(type: String, challenge: String, origin: String): String =
        JSONObject().apply {
            put("type", type)
            put("challenge", challenge)
            put("origin", origin)
            put("crossOrigin", false)
        }.toString()

    private fun authenticatorData(
        rpId: String,
        flags: Int,
        signCount: Long,
        attestedCredentialData: ByteArray?
    ): ByteArray {
        val counter = byteArrayOf(
            ((signCount ushr 24) and 0xff).toByte(),
            ((signCount ushr 16) and 0xff).toByte(),
            ((signCount ushr 8) and 0xff).toByte(),
            (signCount and 0xff).toByte()
        )
        return sha256(rpId.toByteArray(Charsets.UTF_8)) + byteArrayOf(flags.toByte()) +
            counter + (attestedCredentialData ?: ByteArray(0))
    }

    private fun attestedCredentialData(credentialId: ByteArray, publicKey: ECPublicKey): ByteArray {
        val aaguid = ByteArray(16)
        val length = byteArrayOf(((credentialId.size ushr 8) and 0xff).toByte(), (credentialId.size and 0xff).toByte())
        return aaguid + length + credentialId + coseKey(publicKey)
    }

    private fun coseKey(publicKey: ECPublicKey): ByteArray =
        Cbor.map(
            Cbor.int(1) to Cbor.int(2),
            Cbor.int(3) to Cbor.int(ALG_ES256),
            Cbor.int(-1) to Cbor.int(1),
            Cbor.int(-2) to Cbor.bytes(fixed(publicKey.w.affineX.toByteArray(), 32)),
            Cbor.int(-3) to Cbor.bytes(fixed(publicKey.w.affineY.toByteArray(), 32))
        )

    private fun fixed(value: ByteArray, size: Int): ByteArray =
        when {
            value.size == size -> value
            value.size > size -> value.copyOfRange(value.size - size, value.size)
            else -> ByteArray(size - value.size) + value
        }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun androidOrigin(info: CallingAppInfo?): String? {
        if (info == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        val signer = info.signingInfo.apkContentsSigners.firstOrNull() ?: return null
        return "android:apk-key-hash:${base64Url(sha256(signer.toByteArray()))}"
    }
}

private object Cbor {
    fun int(value: Int): ByteArray =
        if (value >= 0) major(0, value.toLong()) else major(1, (-1L - value))

    fun bytes(value: ByteArray): ByteArray = major(2, value.size.toLong()) + value

    fun text(value: String): ByteArray = value.toByteArray(Charsets.UTF_8).let { major(3, it.size.toLong()) + it }

    fun map(vararg pairs: Pair<ByteArray, ByteArray>): ByteArray =
        major(5, pairs.size.toLong()) + pairs.fold(ByteArray(0)) { acc, pair -> acc + pair.first + pair.second }

    private fun major(major: Int, value: Long): ByteArray {
        val head = (major shl 5)
        return when {
            value < 24 -> byteArrayOf((head or value.toInt()).toByte())
            value <= 0xff -> byteArrayOf((head or 24).toByte(), value.toByte())
            value <= 0xffff -> byteArrayOf((head or 25).toByte(), (value ushr 8).toByte(), value.toByte())
            else -> byteArrayOf(
                (head or 26).toByte(),
                (value ushr 24).toByte(),
                (value ushr 16).toByte(),
                (value ushr 8).toByte(),
                value.toByte()
            )
        }
    }
}
