package com.safevault.app.importer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CsvImportTest {

    // ── Parsing ────────────────────────────────────────────────────────────

    @Test
    fun `parses plain rows`() {
        val rows = CsvImport.parse("a,b,c\n1,2,3\n")
        assertEquals(listOf(listOf("a", "b", "c"), listOf("1", "2", "3")), rows)
    }

    @Test
    fun `keeps commas inside quoted fields`() {
        val rows = CsvImport.parse("name,notes\nBank,\"one, two, three\"\n")
        assertEquals(listOf("Bank", "one, two, three"), rows[1])
    }

    @Test
    fun `unescapes doubled quotes`() {
        val rows = CsvImport.parse("name\n\"He said \"\"hi\"\"\"\n")
        assertEquals("""He said "hi"""", rows[1][0])
    }

    @Test
    fun `keeps newlines inside quoted fields`() {
        val rows = CsvImport.parse("name,notes\nSite,\"line one\nline two\"\n")
        assertEquals(2, rows.size)
        assertEquals("line one\nline two", rows[1][1])
    }

    @Test
    fun `handles CRLF line endings`() {
        val rows = CsvImport.parse("a,b\r\n1,2\r\n")
        assertEquals(listOf(listOf("a", "b"), listOf("1", "2")), rows)
    }

    @Test
    fun `preserves empty cells`() {
        assertEquals(listOf("a", "", "c"), CsvImport.parse("a,,c\n")[0])
    }

    @Test
    fun `a trailing newline does not create a phantom row`() {
        assertEquals(2, CsvImport.parse("a,b\n1,2\n").size)
    }

    // ── Column detection ───────────────────────────────────────────────────

    @Test
    fun `detects Chrome export columns`() {
        val m = CsvImport.detectMapping(listOf("name", "url", "username", "password", "note"))
        assertEquals(0, m.title)
        assertEquals(1, m.url)
        assertEquals(2, m.username)
        assertEquals(3, m.password)
        assertEquals(4, m.notes)
        assertEquals("Chrome or Edge", m.source)
    }

    @Test
    fun `detects Bitwarden export columns`() {
        val m = CsvImport.detectMapping(
            listOf(
                "folder", "favorite", "type", "name", "notes", "fields", "reprompt",
                "login_uri", "login_username", "login_password", "login_totp"
            )
        )
        assertEquals(3, m.title)
        assertEquals(7, m.url)
        assertEquals(8, m.username)
        assertEquals(9, m.password)
        assertEquals("Bitwarden", m.source)
    }

    @Test
    fun `detects LastPass export columns`() {
        val m = CsvImport.detectMapping(
            listOf("url", "username", "password", "totp", "extra", "name", "grouping", "fav")
        )
        assertEquals(5, m.title)
        assertEquals(0, m.url)
        assertEquals(1, m.username)
        assertEquals(2, m.password)
        assertEquals("LastPass", m.source)
    }

    @Test
    fun `an exact header match beats a substring match`() {
        // "password_hint" must not win over the real "password" column.
        val m = CsvImport.detectMapping(listOf("name", "password_hint", "password"))
        assertEquals(2, m.password)
    }

    @Test
    fun `is case and whitespace insensitive`() {
        val m = CsvImport.detectMapping(listOf(" Name ", "URL", "  Username", "PASSWORD"))
        assertEquals(0, m.title)
        assertEquals(3, m.password)
    }

    @Test
    fun `tolerates a UTF-8 BOM on the first header cell`() {
        val m = CsvImport.detectMapping(listOf("﻿name", "url", "username", "password"))
        assertEquals(0, m.title)
        assertEquals(3, m.password)
    }

    @Test
    fun `a header with no password column is unusable`() {
        assertTrue(!CsvImport.detectMapping(listOf("name", "url", "username")).isUsable)
    }

    // ── Import ─────────────────────────────────────────────────────────────

    private val chrome = """
        name,url,username,password,note
        Gmail,https://mail.google.com/,me@example.com,s3cret,work account
        GitHub,https://github.com/login,octocat,hunter2,
    """.trimIndent() + "\n"

    @Test
    fun `imports rows into drafts`() {
        val report = CsvImport.read(chrome)
        assertEquals(2, report.imported)
        assertEquals(2, report.totalRows)
        assertEquals(0, report.skipped)

        val gmail = report.drafts[0]
        assertEquals("Gmail", gmail.title)
        assertEquals("me@example.com", gmail.username)
        assertEquals("s3cret", gmail.password)
        assertEquals("work account", gmail.notes)
    }

    @Test
    fun `groups imported rows by host so they land under one service`() {
        val report = CsvImport.read(chrome)
        assertEquals("mail.google.com", report.drafts[0].serviceName)
        assertEquals("github.com", report.drafts[1].serviceName)
    }

    @Test
    fun `counts rows with no password as skipped rather than importing blanks`() {
        val csv = "name,url,username,password\nA,https://a.com,u,pw\nB,https://b.com,u,\n"
        val report = CsvImport.read(csv)
        assertEquals(1, report.imported)
        assertEquals(1, report.skippedNoPassword)
    }

    @Test
    fun `ignores blank lines without counting them as errors`() {
        val csv = "name,url,username,password\nA,https://a.com,u,pw\n\n"
        val report = CsvImport.read(csv)
        assertEquals(1, report.imported)
        assertEquals(0, report.skipped)
    }

    @Test
    fun `falls back to the host when a row has no name`() {
        val csv = "name,url,username,password\n,https://example.com/login,u,pw\n"
        val draft = CsvImport.read(csv).drafts.single()
        assertEquals("example.com", draft.title)
    }

    @Test
    fun `tolerates rows shorter than the header`() {
        val csv = "name,url,username,password,note\nA,https://a.com,u,pw\n"
        val draft = CsvImport.read(csv).drafts.single()
        assertEquals("", draft.notes)
    }

    @Test
    fun `rejects a file with no password column`() {
        try {
            CsvImport.read("name,url\nA,https://a.com\n")
            fail("Expected rejection")
        } catch (e: CsvImport.MalformedCsvException) {
            assertTrue(e.message!!.contains("password"))
        }
    }

    @Test
    fun `rejects an empty file`() {
        try {
            CsvImport.read("")
            fail("Expected rejection")
        } catch (e: CsvImport.MalformedCsvException) {
            assertTrue(e.message!!.contains("empty"))
        }
    }

    // ── Host extraction ────────────────────────────────────────────────────

    @Test
    fun `extracts hosts from assorted url shapes`() {
        assertEquals("mail.google.com", CsvImport.hostOf("https://mail.google.com/mail/u/0"))
        assertEquals("example.com", CsvImport.hostOf("http://www.example.com"))
        assertEquals("example.com", CsvImport.hostOf("example.com/path?q=1"))
        assertEquals("example.com", CsvImport.hostOf("https://example.com:8443/in"))
        assertEquals("", CsvImport.hostOf(""))
    }

    @Test
    fun `strips sign-in subdomains so one service does not split in two`() {
        assertEquals("spotify.com", CsvImport.hostOf("https://accounts.spotify.com"))
        assertEquals("spotify.com", CsvImport.hostOf("https://spotify.com"))
        assertEquals("atlassian.com", CsvImport.hostOf("https://id.atlassian.com/login"))
        assertEquals("ea.com", CsvImport.hostOf("https://signin.ea.com/p/juno"))
    }

    @Test
    fun `does not strip a prefix that is the whole name`() {
        // A site genuinely called login.com must keep its name.
        assertEquals("login.com", CsvImport.hostOf("https://login.com"))
    }
}
