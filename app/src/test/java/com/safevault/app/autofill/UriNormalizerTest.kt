package com.safevault.app.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * These are the tests that matter most in Phase 3.
 *
 * Everything else in autofill fails visibly when it is wrong — a dataset does
 * not appear, a field is not filled. A mistake here fails *invisibly and in the
 * user's favour right up until it doesn't*: a credential offered on a domain it
 * does not belong to looks exactly like a credential offered on one it does.
 */
class UriNormalizerTest {

    // ── Normalisation ──────────────────────────────────────────────────────

    @Test
    fun `reduces a url to a bare comparable host`() {
        assertEquals("example.com", UriNormalizer.normalizeHost("https://example.com/login?next=/a"))
        assertEquals("example.com", UriNormalizer.normalizeHost("HTTP://Example.COM"))
        assertEquals("example.com", UriNormalizer.normalizeHost("example.com:8443"))
        assertEquals("example.com", UriNormalizer.normalizeHost("https://www.example.com"))
        assertEquals("example.com", UriNormalizer.normalizeHost("  example.com.  "))
        assertEquals("mail.example.com", UriNormalizer.normalizeHost("https://mail.example.com/x"))
    }

    @Test
    fun `strips credentials embedded in the url`() {
        // The classic phishing url: everything before the @ is decoration.
        assertEquals(
            "evil.com",
            UriNormalizer.normalizeHost("https://www.paypal.com@evil.com/login")
        )
    }

    @Test
    fun `refuses things that cannot be a web binding`() {
        assertEquals("", UriNormalizer.normalizeHost(""))
        assertEquals("", UriNormalizer.normalizeHost("   "))
        assertEquals("", UriNormalizer.normalizeHost("localhost"))
        assertEquals("", UriNormalizer.normalizeHost("javascript:alert(1)"))
        assertEquals("", UriNormalizer.normalizeHost("mailto:a@b.com"))
        assertEquals("", UriNormalizer.normalizeHost("ftp://files.example.com"))
        assertEquals("", UriNormalizer.normalizeHost("nodots"))
        assertEquals("", UriNormalizer.normalizeHost("double..dot.com"))
        assertEquals("", UriNormalizer.normalizeHost("-leading.example.com"))
    }

    @Test
    fun `keeps www when removing it would leave a bare registrable domain`() {
        // "www.com" is a real registrable domain; stripping the prefix would
        // turn a specific site into the meaningless host "com".
        assertEquals("www.com", UriNormalizer.normalizeHost("http://www.com"))
    }

    // ── Package names ──────────────────────────────────────────────────────

    @Test
    fun `accepts real application ids and rejects malformed ones`() {
        assertEquals("com.google.android.gm", UriNormalizer.normalizePackage("com.google.android.gm"))
        assertEquals("com.example.app_two", UriNormalizer.normalizePackage(" com.example.app_two "))
        assertEquals("", UriNormalizer.normalizePackage("nodots"))
        assertEquals("", UriNormalizer.normalizePackage("com..example"))
        assertEquals("", UriNormalizer.normalizePackage("com.1example"))
        assertEquals("", UriNormalizer.normalizePackage("com.exa mple"))
        assertEquals("", UriNormalizer.normalizePackage(""))
    }

    // ── Registrable domain ─────────────────────────────────────────────────

    @Test
    fun `finds the registrable domain including multi label suffixes`() {
        assertEquals("example.com", UriNormalizer.registrableDomain("login.example.com"))
        assertEquals("example.com", UriNormalizer.registrableDomain("a.b.c.example.com"))
        assertEquals("bbc.co.uk", UriNormalizer.registrableDomain("www.bbc.co.uk"))
        assertEquals("bbc.co.uk", UriNormalizer.registrableDomain("news.bbc.co.uk"))
        assertEquals("user.github.io", UriNormalizer.registrableDomain("blog.user.github.io"))
    }

    @Test
    fun `recognises bare public suffixes`() {
        assertTrue(UriNormalizer.isPublicSuffixOnly("com"))
        assertTrue(UriNormalizer.isPublicSuffixOnly("co.uk"))
        assertTrue(UriNormalizer.isPublicSuffixOnly("github.io"))
        assertFalse(UriNormalizer.isPublicSuffixOnly("example.com"))
        assertFalse(UriNormalizer.isPublicSuffixOnly("bbc.co.uk"))
    }

    // ── Matching ───────────────────────────────────────────────────────────

    @Test
    fun `a binding fills its own host and its subdomains`() {
        assertTrue(UriNormalizer.hostMatches("example.com", "example.com"))
        assertTrue(UriNormalizer.hostMatches("example.com", "login.example.com"))
        assertTrue(UriNormalizer.hostMatches("example.com", "a.b.example.com"))
        assertTrue(UriNormalizer.hostMatches("example.com", "https://login.example.com/in"))
    }

    @Test
    fun `a binding does not fill a lookalike domain`() {
        // The dot boundary is the whole defence here.
        assertFalse(UriNormalizer.hostMatches("example.com", "notexample.com"))
        assertFalse(UriNormalizer.hostMatches("example.com", "example.com.evil.net"))
        assertFalse(UriNormalizer.hostMatches("example.com", "myexample.com"))
        assertFalse(UriNormalizer.hostMatches("paypal.com", "paypal.com-login.ru"))
    }

    @Test
    fun `matching does not walk up the tree`() {
        // A binding for one subdomain says nothing about its siblings or parent.
        assertFalse(UriNormalizer.hostMatches("login.example.com", "example.com"))
        assertFalse(UriNormalizer.hostMatches("a.example.com", "b.example.com"))
    }

    @Test
    fun `a bare public suffix binding matches nothing`() {
        assertFalse(UriNormalizer.hostMatches("com", "example.com"))
        assertFalse(UriNormalizer.hostMatches("co.uk", "bbc.co.uk"))
        assertFalse(UriNormalizer.hostMatches("github.io", "someone.github.io"))
    }

    @Test
    fun `ip literals only match themselves`() {
        assertTrue(UriNormalizer.hostMatches("192.168.1.10", "192.168.1.10"))
        assertFalse(UriNormalizer.hostMatches("192.168.1.10", "a.192.168.1.10"))
    }

    @Test
    fun `empty input never matches`() {
        assertFalse(UriNormalizer.hostMatches("", "example.com"))
        assertFalse(UriNormalizer.hostMatches("example.com", ""))
        assertFalse(UriNormalizer.hostMatches("", ""))
    }

    // ── The two implementations must agree ─────────────────────────────────

    @Test
    fun `candidate expansion yields exactly the hosts that match`() {
        val hosts = listOf(
            "example.com", "login.example.com", "a.b.c.example.com",
            "news.bbc.co.uk", "someone.github.io", "192.168.1.10"
        )
        for (request in hosts) {
            for (candidate in UriNormalizer.expandHostCandidates(request)) {
                assertTrue(
                    "expandHostCandidates offered '$candidate' for '$request' " +
                        "but hostMatches rejects it",
                    UriNormalizer.hostMatches(candidate, request)
                )
            }
        }
    }

    @Test
    fun `candidate expansion stops at the registrable domain`() {
        assertEquals(
            listOf("a.b.example.com", "b.example.com", "example.com"),
            UriNormalizer.expandHostCandidates("a.b.example.com")
        )
        // Never "co.uk": the query must not be able to hit a whole-TLD binding.
        assertEquals(
            listOf("news.bbc.co.uk", "bbc.co.uk"),
            UriNormalizer.expandHostCandidates("news.bbc.co.uk")
        )
        assertEquals(listOf("example.com"), UriNormalizer.expandHostCandidates("example.com"))
        assertEquals(emptyList<String>(), UriNormalizer.expandHostCandidates("localhost"))
    }

    @Test
    fun `expansion never offers a bare public suffix`() {
        val requests = listOf(
            "a.b.example.com", "news.bbc.co.uk", "x.y.someone.github.io", "deep.a.b.c.example.co.jp"
        )
        for (request in requests) {
            for (candidate in UriNormalizer.expandHostCandidates(request)) {
                assertFalse(
                    "expansion offered the public suffix '$candidate' for '$request'",
                    UriNormalizer.isPublicSuffixOnly(candidate)
                )
            }
        }
    }
}
