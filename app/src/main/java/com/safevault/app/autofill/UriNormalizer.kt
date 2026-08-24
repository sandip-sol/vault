package com.safevault.app.autofill

/**
 * Turns whatever a fill request hands us into a value that can be *compared*
 * rather than parsed.
 *
 * Every function here is pure and JVM-testable on purpose. This is the code that
 * decides whether a stored credential belongs to the app now asking for it, so
 * it is the one part of autofill that must be exercised by tests rather than by
 * trying it in Chrome and seeing what happens.
 */
object UriNormalizer {

    /**
     * Multi-label public suffixes common enough to matter here.
     *
     * This is deliberately *not* a public suffix list. A real PSL is ~10k entries
     * that has to be shipped and kept current, and the only thing this code needs
     * it for is a safety check: refusing to treat a bare suffix as a service
     * identity. A binding of `co.uk` would otherwise match every British site in
     * existence. The list being incomplete costs nothing — an unlisted suffix
     * simply falls back to the ordinary two-label rule — whereas the list being
     * absent costs a cross-domain fill.
     */
    private val MULTI_LABEL_SUFFIXES = setOf(
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "com.br", "net.br", "org.br", "gov.br",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "co.za", "org.za", "net.za",
        "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw",
        "co.kr", "or.kr",
        "com.pl", "com.ua", "co.il", "com.my", "co.th", "com.ph",
        "github.io", "gitlab.io", "herokuapp.com", "web.app", "firebaseapp.com",
        "pages.dev", "workers.dev", "vercel.app", "netlify.app", "azurewebsites.net"
    )

    /** Hosts that are never a service identity — no credential belongs to them. */
    private val UNBINDABLE_HOSTS = setOf("localhost", "127.0.0.1", "::1", "0.0.0.0")

    /**
     * Normalises a web URL or bare host to the form stored in
     * [com.safevault.app.data.UriBinding.value]: lowercase host, no scheme, no
     * credentials, no port, no path, no trailing dot, no leading `www.`.
     *
     * @return the normalised host, or "" if the input cannot be a binding.
     */
    fun normalizeHost(input: String): String {
        var host = input.trim().lowercase()
        if (host.isEmpty()) return ""

        // Strip the scheme. Anything that is not http(s) is not a web origin we
        // will bind — a `javascript:` or `data:` "host" is a parsing artefact.
        val schemeEnd = host.indexOf("://")
        if (schemeEnd >= 0) {
            val scheme = host.substring(0, schemeEnd)
            if (scheme != "http" && scheme != "https") return ""
            host = host.substring(schemeEnd + 3)
        } else if (host.contains(':') && !host.substringBefore(':').all { it.isDigit() }) {
            // A scheme with no slashes, e.g. "mailto:x@y" — not a web origin.
            val head = host.substringBefore(':')
            if (head.isNotEmpty() && head.all { it.isLetter() } && head != "localhost") return ""
        }

        // userinfo@host
        val at = host.lastIndexOf('@')
        if (at >= 0) host = host.substring(at + 1)

        // Cut path, query and fragment before the port, so that a ':' inside a
        // path cannot be mistaken for a port separator.
        host = host.substringBefore('/').substringBefore('?').substringBefore('#')

        // Port. Guarded so an IPv6 literal's colons are not treated as one.
        if (!host.startsWith("[")) host = host.substringBefore(':')

        host = host.trimEnd('.')
        if (host.isEmpty()) return ""
        if (host in UNBINDABLE_HOSTS) return ""

        if (host.startsWith("www.") && host.count { it == '.' } >= 2) {
            host = host.removePrefix("www.")
        }

        return if (isPlausibleHost(host)) host else ""
    }

    /**
     * Normalises an Android application id. Package names are already canonical,
     * so this only validates: a malformed one must not become a binding that
     * some other malformed string later equals.
     *
     * @return the package name, or "" if it is not a plausible application id.
     */
    fun normalizePackage(input: String): String {
        val pkg = input.trim()
        if (pkg.isEmpty() || !pkg.contains('.')) return ""
        val labels = pkg.split('.')
        if (labels.any { label ->
                label.isEmpty() ||
                    !label.first().isJavaIdentifierStart() ||
                    !label.all { it.isJavaIdentifierPart() }
            }
        ) {
            return ""
        }
        return pkg
    }

    /**
     * The registrable domain — `example.com` for `login.example.com`, and
     * `bbc.co.uk` rather than `co.uk` for `www.bbc.co.uk`.
     *
     * Used to *suggest* a binding when saving a new credential, and to rank a
     * same-site match above a same-registrable-domain one. It is not used to
     * decide whether a fill is allowed; [hostMatches] does that.
     */
    fun registrableDomain(host: String): String {
        val h = normalizeHost(host)
        if (h.isEmpty() || isIpLiteral(h)) return h
        val labels = h.split('.')
        if (labels.size < 2) return h

        val lastTwo = labels.takeLast(2).joinToString(".")
        val take = if (lastTwo in MULTI_LABEL_SUFFIXES) 3 else 2
        return if (labels.size <= take) h else labels.takeLast(take).joinToString(".")
    }

    /**
     * True when [host] is nothing but a public suffix, e.g. `co.uk` or `com`.
     *
     * Deliberately does not go through [normalizeHost], which rejects a dotless
     * host as implausible — "com" is exactly the input this has to be able to
     * answer "yes" about, and normalising it first would answer "no".
     */
    fun isPublicSuffixOnly(host: String): Boolean {
        val h = host.trim().lowercase().trimEnd('.').substringBefore('/')
        if (h.isEmpty() || isIpLiteral(h)) return false
        return !h.contains('.') || h in MULTI_LABEL_SUFFIXES
    }

    /**
     * Whether a stored binding may fill a request for [requestHost].
     *
     * The rule is exact host, or [requestHost] being a subdomain of the binding.
     * The dot boundary is the load-bearing part: without it `example.com` would
     * match `notexample.com`, which is precisely the shape of a phishing domain.
     *
     * The relation is deliberately one-way. A binding on `example.com` fills
     * `login.example.com`, because a user who says "this is my Example account"
     * means the site. A binding on `login.example.com` does *not* fill
     * `example.com`, and more importantly does not fill some other subdomain: on
     * shared hosts, sibling subdomains are different parties.
     */
    fun hostMatches(bindingHost: String, requestHost: String): Boolean {
        val binding = normalizeHost(bindingHost)
        val request = normalizeHost(requestHost)
        if (binding.isEmpty() || request.isEmpty()) return false
        if (binding == request) return true
        // A bare public suffix is not an identity; it would match a whole TLD.
        if (isPublicSuffixOnly(binding)) return false
        if (isIpLiteral(binding) || isIpLiteral(request)) return false
        return request.endsWith(".$binding")
    }

    /**
     * Every host a binding could legally hold and still match [requestHost] —
     * the host itself and each parent label down to the registrable domain.
     *
     * This is the SQL-side counterpart to [hostMatches]: expanding the request
     * lets the binding lookup stay an indexed `value IN (...)` equality search
     * instead of loading every binding and comparing suffixes in memory. The two
     * must agree, and a test asserts that they do.
     */
    fun expandHostCandidates(requestHost: String): List<String> {
        val host = normalizeHost(requestHost)
        if (host.isEmpty()) return emptyList()
        if (isIpLiteral(host)) return listOf(host)

        val registrable = registrableDomain(host)
        val candidates = mutableListOf(host)
        var current = host
        while (current != registrable && current.contains('.')) {
            current = current.substringAfter('.')
            if (current.isEmpty() || isPublicSuffixOnly(current)) break
            candidates += current
            if (current == registrable) break
        }
        return candidates.distinct()
    }

    private fun isIpLiteral(host: String): Boolean =
        host.startsWith("[") || host.split('.').let { parts ->
            parts.size == 4 && parts.all { p ->
                p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && p.toInt() <= 255
            }
        }

    /**
     * A host has at least one dot, no empty labels, and only characters that can
     * appear in one. Punycode arrives already encoded as `xn--…`, which passes.
     */
    private fun isPlausibleHost(host: String): Boolean {
        if (host.startsWith("[")) return host.endsWith("]") && host.length > 2
        if (!host.contains('.')) return false
        if (host.length > 253) return false
        return host.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 &&
                !label.startsWith('-') && !label.endsWith('-') &&
                label.all { it.isLetterOrDigit() || it == '-' || it == '_' }
        }
    }
}
