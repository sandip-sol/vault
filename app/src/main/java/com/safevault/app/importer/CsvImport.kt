package com.safevault.app.importer

import com.safevault.app.autofill.UriNormalizer
import com.safevault.app.data.CredentialDraft

/**
 * Reads the CSV that every other password manager exports.
 *
 * There is no CSV standard worth the name here — Chrome writes
 * `name,url,username,password`, Bitwarden writes `name,login_uri,login_username,
 * login_password`, LastPass writes `url,username,password,...,name`, and so on.
 * Rather than ask the user to describe their file, [detectMapping] recognises the
 * header row and falls back to a generic match on column names.
 *
 * Everything here is pure string handling with no Android dependency, so the
 * quoting rules and the mapping table are testable on the JVM — which matters,
 * because a mis-mapped column silently files someone's password under "username".
 */
object CsvImport {

    /** Which column index carries which field. -1 means "not present". */
    data class Mapping(
        val source: String,
        val title: Int,
        val username: Int,
        val password: Int,
        val url: Int = -1,
        val notes: Int = -1
    ) {
        val isUsable: Boolean get() = password >= 0 && (title >= 0 || url >= 0)
    }

    data class Report(
        val drafts: List<CredentialDraft>,
        val mapping: Mapping,
        val totalRows: Int,
        val skippedNoPassword: Int,
        val skippedMalformed: Int
    ) {
        val imported: Int get() = drafts.size
        val skipped: Int get() = skippedNoPassword + skippedMalformed
    }

    class MalformedCsvException(message: String) : Exception(message)

    // ── Header recognition ─────────────────────────────────────────────────

    private val TITLE_KEYS = listOf("name", "title", "account", "item", "display name")
    private val USER_KEYS = listOf(
        "username", "user name", "login_username", "login name", "user", "email", "login"
    )
    private val PASSWORD_KEYS = listOf("password", "login_password", "pass", "secret")
    private val URL_KEYS = listOf("url", "uri", "login_uri", "website", "site", "web site", "hostname")
    private val NOTES_KEYS = listOf("notes", "note", "comment", "comments", "extra")

    /**
     * Picks columns from the header row. Exact matches win over substring
     * matches so that a "password" column is never lost to "password_hint",
     * and so `login_username` does not get claimed by the `login` alias.
     */
    fun detectMapping(header: List<String>): Mapping {
        // Excel and several exporters prefix the file with a UTF-8 BOM.
        val cells = header.map { it.trim().lowercase().removePrefix("\uFEFF") }

        fun find(keys: List<String>): Int {
            keys.forEach { key ->
                val exact = cells.indexOf(key)
                if (exact >= 0) return exact
            }
            keys.forEach { key ->
                val partial = cells.indexOfFirst { it.contains(key) }
                if (partial >= 0) return partial
            }
            return -1
        }

        val password = find(PASSWORD_KEYS)
        val username = find(USER_KEYS).takeIf { it != password } ?: -1
        val title = find(TITLE_KEYS)
        val url = find(URL_KEYS)
        val notes = find(NOTES_KEYS)

        return Mapping(
            source = describeSource(cells),
            title = title,
            username = username,
            password = password,
            url = url,
            notes = notes
        )
    }

    /** Best-effort label for the export's origin, shown in the import preview. */
    private fun describeSource(cells: List<String>): String = when {
        cells.containsAll(listOf("name", "url", "username", "password")) &&
            cells.contains("note") -> "Chrome or Edge"
        cells.any { it.startsWith("login_") } -> "Bitwarden"
        cells.contains("grouping") && cells.contains("fav") -> "LastPass"
        cells.contains("type") && cells.contains("title") -> "1Password"
        cells.contains("web site") || cells.contains("login name") -> "Keeper"
        else -> "Generic CSV"
    }

    // ── Parsing ────────────────────────────────────────────────────────────

    /**
     * Splits CSV text into rows of cells, honouring quoted fields, escaped
     * doubled quotes and newlines inside quotes. Accepts CRLF and LF.
     */
    fun parse(text: String): List<List<String>> {
        val rows = mutableListOf<List<String>>()
        var row = mutableListOf<String>()
        val cell = StringBuilder()
        var inQuotes = false
        var i = 0

        fun endCell() {
            row.add(cell.toString())
            cell.setLength(0)
        }

        fun endRow() {
            endCell()
            // A trailing newline would otherwise produce a phantom empty row.
            if (row.size > 1 || row.firstOrNull()?.isNotEmpty() == true) rows.add(row)
            row = mutableListOf()
        }

        while (i < text.length) {
            val c = text[i]
            when {
                inQuotes && c == '"' && i + 1 < text.length && text[i + 1] == '"' -> {
                    cell.append('"'); i++
                }
                c == '"' -> inQuotes = !inQuotes
                !inQuotes && c == ',' -> endCell()
                !inQuotes && c == '\r' -> Unit
                !inQuotes && c == '\n' -> endRow()
                else -> cell.append(c)
            }
            i++
        }
        if (cell.isNotEmpty() || row.isNotEmpty()) endRow()

        return rows
    }

    // ── Import ─────────────────────────────────────────────────────────────

    fun read(text: String): Report {
        val rows = parse(text)
        if (rows.isEmpty()) throw MalformedCsvException("The file is empty")

        val mapping = detectMapping(rows.first())
        if (!mapping.isUsable) {
            throw MalformedCsvException(
                "No password column found. Expected a header row naming the columns."
            )
        }

        val drafts = mutableListOf<CredentialDraft>()
        var noPassword = 0
        var malformed = 0

        rows.drop(1).forEach { cells ->
            fun cell(index: Int): String =
                if (index in cells.indices) cells[index].trim() else ""

            val password = cell(mapping.password)
            val title = cell(mapping.title)
            val url = cell(mapping.url)

            when {
                cells.all { it.isBlank() } -> Unit                 // blank line, not an error
                password.isEmpty() -> noPassword++
                title.isEmpty() && url.isEmpty() -> malformed++
                else -> {
                    val label = title.ifEmpty { hostOf(url) }
                    drafts += CredentialDraft(
                        title = label,
                        // Grouping key: entries from the same site land together,
                        // which is the whole point of importing rather than retyping.
                        serviceName = hostOf(url).ifEmpty { label },
                        website = url,
                        username = cell(mapping.username),
                        password = password,
                        notes = cell(mapping.notes)
                    )
                }
            }
        }

        return Report(
            drafts = drafts,
            mapping = mapping,
            totalRows = rows.size - 1,
            skippedNoPassword = noPassword,
            skippedMalformed = malformed
        )
    }

    /**
     * Sign-in subdomains that exist only to host a login form. Stripping them
     * keeps `accounts.spotify.com` and `spotify.com` in one service group
     * instead of two.
     */
    private val LOGIN_SUBDOMAINS =
        listOf("accounts.", "account.", "login.", "signin.", "sso.", "auth.", "id.", "my.")

    /**
     * `https://accounts.spotify.com/path` -> `spotify.com`.
     *
     * The URL parsing is [UriNormalizer]'s, so importing and autofill agree on
     * what a host is; only the sign-in-prefix stripping above is local. That
     * stripping is a grouping heuristic and nothing more — it decides which
     * header an imported row lands under and the fallback title, never which
     * credential a fill request is offered. Binding a *matchable* host is
     * [com.safevault.app.data.VaultRepository.bindWebsite]'s job, and it starts
     * from the untouched URL rather than from this.
     */
    internal fun hostOf(url: String): String {
        var host = UriNormalizer.normalizeHost(url)
        if (host.isEmpty()) return ""

        LOGIN_SUBDOMAINS.forEach { prefix ->
            // Only strip when something of substance remains, so a site actually
            // called "login.com" keeps its name.
            if (host.startsWith(prefix) && host.removePrefix(prefix).count { it == '.' } >= 1) {
                host = host.removePrefix(prefix)
            }
        }
        return host
    }
}
