package com.safevault.app.autofill

import android.text.InputType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The classifier decides where a password is typed. Two failure modes matter and
 * they are not symmetric: missing a real password field is an annoyance, and
 * mistaking a search box or a 2FA input for one puts a vault secret somewhere it
 * will be logged, transmitted or displayed. The negative cases below are the
 * point of this suite.
 */
class FieldClassifierTest {

    private fun classify(
        hints: List<String> = emptyList(),
        idEntry: String? = null,
        hint: String? = null,
        htmlName: String? = null,
        htmlType: String? = null,
        htmlId: String? = null,
        contentDescription: String? = null,
        inputType: Int = 0,
        excluded: Boolean = false
    ) = FieldClassifier.classify(
        FieldDescriptor(
            hints, idEntry, hint, htmlName, htmlType, htmlId,
            contentDescription, inputType, excluded
        )
    )

    private val passwordInput =
        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    private val emailInput =
        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS

    // ── Declared hints win ─────────────────────────────────────────────────

    @Test
    fun `autofill hints are taken at their word`() {
        assertEquals(FieldType.PASSWORD, classify(hints = listOf("password")))
        assertEquals(FieldType.USERNAME, classify(hints = listOf("username")))
        assertEquals(FieldType.USERNAME, classify(hints = listOf("emailAddress")))
        assertEquals(FieldType.NEW_PASSWORD, classify(hints = listOf("newPassword")))
    }

    @Test
    fun `a declared hint beats a contradicting name`() {
        // The app said this is a username; the id is misleading. Believe the app.
        assertEquals(
            FieldType.USERNAME,
            classify(hints = listOf("username"), idEntry = "password_field")
        )
    }

    @Test
    fun `an unrecognised hint is skipped rather than guessed at`() {
        // Setting a hint is a statement that the field is something specific.
        // Falling through to keyword matching would override that statement.
        assertEquals(
            FieldType.IGNORED,
            classify(hints = listOf("creditCardNumber"), idEntry = "card_password")
        )
        assertEquals(FieldType.IGNORED, classify(hints = listOf("somethingCustom")))
    }

    @Test
    fun `one time codes are refused even when hinted`() {
        assertEquals(FieldType.IGNORED, classify(hints = listOf("smsOTPCode")))
    }

    // ── HTML forms ─────────────────────────────────────────────────────────

    @Test
    fun `html input types classify browser fields`() {
        assertEquals(FieldType.PASSWORD, classify(htmlType = "password", htmlName = "pass"))
        assertEquals(FieldType.USERNAME, classify(htmlType = "email", htmlName = "email"))
        assertEquals(FieldType.USERNAME, classify(htmlType = "text", htmlName = "username"))
        assertEquals(FieldType.IGNORED, classify(htmlType = "checkbox", htmlName = "remember"))
        assertEquals(FieldType.IGNORED, classify(htmlType = "hidden", htmlName = "csrf_token"))
        assertEquals(FieldType.IGNORED, classify(htmlType = "submit", htmlName = "login"))
    }

    @Test
    fun `a registration form's password box is a new password`() {
        assertEquals(
            FieldType.NEW_PASSWORD,
            classify(htmlType = "password", htmlName = "confirm_password")
        )
        assertEquals(
            FieldType.NEW_PASSWORD,
            classify(htmlType = "password", htmlName = "new_password")
        )
    }

    // ── Native views ───────────────────────────────────────────────────────

    @Test
    fun `input type flags classify native fields`() {
        assertEquals(FieldType.PASSWORD, classify(inputType = passwordInput, idEntry = "et_pass"))
        assertEquals(
            FieldType.PASSWORD,
            classify(
                inputType = InputType.TYPE_CLASS_TEXT or
                    InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            )
        )
        assertEquals(FieldType.USERNAME, classify(inputType = emailInput, idEntry = "et_email"))
    }

    @Test
    fun `names and labels are the last resort`() {
        assertEquals(FieldType.PASSWORD, classify(idEntry = "login_password"))
        assertEquals(FieldType.USERNAME, classify(idEntry = "login_username"))
        assertEquals(FieldType.USERNAME, classify(hint = "Email address"))
        assertEquals(FieldType.PASSWORD, classify(contentDescription = "Passwort"))
    }

    // ── The cases that must never be filled ────────────────────────────────

    @Test
    fun `a search box is never a credential field`() {
        assertEquals(FieldType.IGNORED, classify(idEntry = "search_query"))
        assertEquals(FieldType.IGNORED, classify(htmlType = "search", htmlName = "q"))
        // Even when it is, bizarrely, a password-typed search box.
        assertEquals(
            FieldType.IGNORED,
            classify(inputType = passwordInput, idEntry = "search_password_field")
        )
    }

    @Test
    fun `two factor and card fields are never a credential field`() {
        assertEquals(FieldType.IGNORED, classify(idEntry = "otp_code"))
        assertEquals(FieldType.IGNORED, classify(idEntry = "totp_input"))
        assertEquals(FieldType.IGNORED, classify(hint = "Verification code"))
        assertEquals(FieldType.IGNORED, classify(idEntry = "card_number"))
        assertEquals(FieldType.IGNORED, classify(htmlName = "cvv"))
        assertEquals(
            FieldType.IGNORED,
            classify(inputType = passwordInput, htmlName = "security_code")
        )
    }

    @Test
    fun `a field the app excluded is left alone`() {
        assertEquals(
            FieldType.IGNORED,
            classify(hints = listOf("password"), excluded = true)
        )
    }

    @Test
    fun `an unlabelled plain text box is not guessed at`() {
        assertEquals(FieldType.IGNORED, classify(inputType = InputType.TYPE_CLASS_TEXT))
        assertEquals(FieldType.IGNORED, classify())
        assertEquals(FieldType.IGNORED, classify(idEntry = "et_first_name"))
    }

    // ── Form-level decision ────────────────────────────────────────────────

    @Test
    fun `a form needs at least one credential field`() {
        assertTrue(FieldClassifier.isFillableForm(listOf(FieldType.PASSWORD)))
        assertTrue(FieldClassifier.isFillableForm(listOf(FieldType.USERNAME)))
        assertTrue(
            FieldClassifier.isFillableForm(listOf(FieldType.USERNAME, FieldType.PASSWORD))
        )
        assertTrue(FieldClassifier.isFillableForm(listOf(FieldType.NEW_PASSWORD)))
        assertFalse(FieldClassifier.isFillableForm(listOf(FieldType.IGNORED)))
        assertFalse(FieldClassifier.isFillableForm(emptyList()))
    }
}
