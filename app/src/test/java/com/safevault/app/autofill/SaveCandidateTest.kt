package com.safevault.app.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SaveCandidateTest {

    @Test
    fun `save uses the submitted sign in password`() {
        assertEquals(
            "current",
            SaveCandidate.passwordValueForSave(
                listOf(FieldType.PASSWORD to "current")
            )
        )
    }

    @Test
    fun `save prefers the new password on a change password form`() {
        assertEquals(
            "replacement",
            SaveCandidate.passwordValueForSave(
                listOf(
                    FieldType.PASSWORD to "old-password",
                    FieldType.NEW_PASSWORD to "replacement",
                    FieldType.NEW_PASSWORD to "replacement"
                )
            )
        )
    }

    @Test
    fun `save ignores blank submitted password values`() {
        assertEquals(
            "fallback",
            SaveCandidate.passwordValueForSave(
                listOf(
                    FieldType.NEW_PASSWORD to " ",
                    FieldType.PASSWORD to "fallback"
                )
            )
        )
        assertNull(
            SaveCandidate.passwordValueForSave(
                listOf(FieldType.PASSWORD to "")
            )
        )
    }
}
