package com.safevault.app.credential

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey

@RunWith(RobolectricTestRunner::class)
class WebAuthnTest {

    @Test
    fun `creates none attestation for a saved passkey`() {
        val options = WebAuthn.parseCreationOptions(
            """
            {
              "challenge": "challenge-1",
              "rp": {"id": "example.com", "name": "Example"},
              "user": {"id": "user-handle", "name": "user@example.com", "displayName": "User"}
            }
            """.trimIndent(),
            "https://example.com"
        )
        val credentialId = WebAuthn.base64UrlDecode("AQIDBA")
        val json = JSONObject(
            WebAuthn.createCredentialJson(options, "https://example.com", credentialId, WebAuthn.newKeyPair(), null)
        )

        assertEquals("public-key", json.getString("type"))
        assertEquals("AQIDBA", json.getString("id"))
        assertTrue(json.getJSONObject("response").getString("attestationObject").isNotBlank())
    }

    @Test
    fun `assertion signature verifies against the saved public key`() {
        val keyPair = WebAuthn.newKeyPair()
        val options = WebAuthn.parseRequestOptions(
            """{"rpId":"example.com","challenge":"challenge-2"}"""
        )
        val json = JSONObject(
            WebAuthn.getCredentialJson(
                options = options,
                origin = "https://example.com",
                packageName = "",
                credentialId = "cred-1",
                userHandle = "user-handle",
                privateKey = WebAuthn.privateKeyFromBase64Url(WebAuthn.encodedPrivateKey(keyPair)),
                signCount = 1,
                clientDataHash = null
            )
        )

        val response = json.getJSONObject("response")
        val authData = WebAuthn.base64UrlDecode(response.getString("authenticatorData"))
        val clientData = WebAuthn.base64UrlDecode(response.getString("clientDataJSON"))
        val signature = WebAuthn.base64UrlDecode(response.getString("signature"))
        val signed = authData + MessageDigest.getInstance("SHA-256").digest(clientData)

        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(keyPair.public as ECPublicKey)
            update(signed)
            verify(signature)
        }
        assertTrue(ok)
    }
}
