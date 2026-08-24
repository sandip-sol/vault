package com.safevault.app.autofill

import android.text.InputType
import android.view.View

/**
 * What a form field is, as far as filling it is concerned.
 */
enum class FieldType {
    USERNAME,
    PASSWORD,

    /**
     * A password field on a registration or change-password form. It is filled
     * with a *generated* value, never an existing one, and its presence is what
     * turns a save prompt into an update prompt.
     */
    NEW_PASSWORD,

    /**
     * A one-time code, CAPTCHA, PIN or search box. Explicitly recognised rather
     * than merely unmatched: these are the fields most likely to be mistaken for
     * a password by a keyword rule, and putting a vault password in one leaks it
     * to whatever reads that field.
     */
    IGNORED
}

/**
 * A form field reduced to the attributes classification actually uses.
 *
 * The Android view tree is flattened into these by [StructureParser] so that the
 * decision "is this a password box?" is a pure function over data, and can be
 * tested against the real shapes browsers and apps produce instead of only being
 * tried by hand against whatever happens to be installed.
 */
data class FieldDescriptor(
    /** `android:autofillHints` — authoritative when the app bothered to set it. */
    val hints: List<String> = emptyList(),
    /** The resource entry name, e.g. `login_password` from `@id/login_password`. */
    val idEntry: String? = null,
    /** `android:hint`, or a placeholder in a web form. */
    val hint: String? = null,
    /** The `name` attribute of an HTML input. */
    val htmlName: String? = null,
    /** The `type` attribute of an HTML input. */
    val htmlType: String? = null,
    /** The `id` attribute of an HTML input. */
    val htmlId: String? = null,
    /** Text near the field: content description, label, or the node's own text. */
    val contentDescription: String? = null,
    /** [InputType] flags from the view. 0 when unknown. */
    val inputType: Int = 0,
    /** [View.getImportantForAutofill] said no. */
    val excluded: Boolean = false
)

/**
 * Decides what each field on a form is.
 *
 * The order matters and is the whole design: explicit autofill hints beat the
 * HTML `type` attribute, which beats [InputType] flags, which beat guessing from
 * names. Each step down that list is less trustworthy, so anything that can be
 * decided higher up never reaches the guessing.
 */
object FieldClassifier {

    // Android and W3C autofill hint constants, lowercased for comparison.
    private val USERNAME_HINTS = setOf(
        "username", "email", "emailaddress", "email-address", "phone",
        "tel", "telephone", "personname", "name", "nickname"
    )
    private val PASSWORD_HINTS = setOf("password", "current-password")
    private val NEW_PASSWORD_HINTS = setOf("newpassword", "new-password", "newusername")
    private val IGNORED_HINTS = setOf(
        "smsotpcode", "one-time-code", "otp", "creditcardnumber",
        "creditcardsecuritycode", "creditcardexpirationdate", "postaladdress",
        "postalcode", "cc-number", "cc-csc", "cc-exp"
    )

    /**
     * Words that mean "not a credential" even when something else on the field
     * says otherwise. Checked before the positive rules, because a keyword like
     * "code" appearing next to "password" must lose.
     */
    private val NEGATIVE_KEYWORDS = listOf(
        "search", "query", "captcha", "otp", "one_time", "onetime", "one-time",
        "verification", "verify_code", "authcode", "auth_code", "2fa", "totp",
        "mfa", "pin_code", "securitycode", "security_code", "cvv", "cvc",
        "cardnumber", "card_number", "creditcard", "credit_card", "expiry",
        "coupon", "promo", "postcode", "zipcode", "zip_code"
    )

    private val PASSWORD_KEYWORDS = listOf(
        "password", "passwd", "pwd", "pass_word", "passphrase",
        // Non-English labels are common enough on sites that never set a hint,
        // and a missed one silently means "no dataset offered here, ever".
        "passwort", "kennwort", "contrasena", "contraseña", "motdepasse",
        "mot_de_passe", "senha", "wachtwoord", "lösenord", "salasana", "hasło"
    )

    private val NEW_PASSWORD_KEYWORDS = listOf(
        "newpassword", "new_password", "new-password", "password_new",
        "password_confirm", "confirm_password", "confirmpassword", "password2",
        "repeat_password", "retype", "register_password", "signup_password"
    )

    private val USERNAME_KEYWORDS = listOf(
        "username", "user_name", "userid", "user_id", "login", "loginid",
        "email", "e_mail", "emailaddress", "account", "identifier", "handle",
        "benutzername", "usuario", "utilisateur"
    )

    /**
     * @return the field's type, or [FieldType.IGNORED] when nothing should be
     *   put in it.
     */
    fun classify(field: FieldDescriptor): FieldType {
        if (field.excluded) return FieldType.IGNORED

        // 1. Declared hints. An app that sets these has told us the answer.
        val hints = field.hints.map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        if (hints.isNotEmpty()) {
            if (hints.any { it in IGNORED_HINTS }) return FieldType.IGNORED
            if (hints.any { it in NEW_PASSWORD_HINTS }) return FieldType.NEW_PASSWORD
            if (hints.any { it in PASSWORD_HINTS }) return FieldType.PASSWORD
            if (hints.any { it in USERNAME_HINTS }) return FieldType.USERNAME
            // A hint we do not recognise is still a statement that this field is
            // something else. Guessing past it does more harm than skipping.
            return FieldType.IGNORED
        }

        val haystack = haystack(field)
        if (NEGATIVE_KEYWORDS.any { haystack.contains(it) }) return FieldType.IGNORED

        // 2. The HTML type attribute, for fields inside a browser.
        when (field.htmlType?.trim()?.lowercase()) {
            "password" -> return if (NEW_PASSWORD_KEYWORDS.any { haystack.contains(it) }) {
                FieldType.NEW_PASSWORD
            } else {
                FieldType.PASSWORD
            }
            "email" -> return FieldType.USERNAME
            "tel" -> return FieldType.USERNAME
            "hidden", "submit", "button", "checkbox", "radio", "file", "range",
            "color", "date", "datetime-local", "month", "week", "time", "number",
            "search" -> return FieldType.IGNORED
        }

        // 3. InputType flags, for native views.
        if (isPasswordInputType(field.inputType)) {
            return if (NEW_PASSWORD_KEYWORDS.any { haystack.contains(it) }) {
                FieldType.NEW_PASSWORD
            } else {
                FieldType.PASSWORD
            }
        }

        // 4. Names and labels — the least trustworthy signal, so it runs last.
        if (haystack.isNotEmpty()) {
            if (NEW_PASSWORD_KEYWORDS.any { haystack.contains(it) }) return FieldType.NEW_PASSWORD
            if (PASSWORD_KEYWORDS.any { haystack.contains(it) }) return FieldType.PASSWORD
            if (USERNAME_KEYWORDS.any { haystack.contains(it) }) return FieldType.USERNAME
            if (isEmailInputType(field.inputType)) return FieldType.USERNAME
        }

        return FieldType.IGNORED
    }

    /**
     * Whether a set of classified fields looks like a form worth offering
     * credentials for.
     *
     * A lone username box is a form (plenty of sites ask for the identifier
     * first, then the password on the next screen). A lone password box is a
     * form. Neither is: offering a dataset there is how a fill lands in a search
     * box.
     */
    fun isFillableForm(types: Collection<FieldType>): Boolean =
        types.any { it == FieldType.USERNAME || it == FieldType.PASSWORD || it == FieldType.NEW_PASSWORD }

    /**
     * Everything that might name the field, lowercased into one string.
     *
     * Concatenation is deliberate. These attributes are alternatives, not a
     * hierarchy — one app puts "password" in the resource id, another in the
     * hint, a third in the content description — and there is no useful ordering
     * between them once the trustworthy signals above have already been tried.
     */
    private fun haystack(field: FieldDescriptor): String = buildString {
        listOfNotNull(
            field.idEntry, field.hint, field.htmlName, field.htmlId, field.contentDescription
        ).forEach { append(it.lowercase()).append(' ') }
    }.trim()

    private fun isPasswordInputType(inputType: Int): Boolean {
        if (inputType == 0) return false
        val cls = inputType and InputType.TYPE_MASK_CLASS
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        return when (cls) {
            InputType.TYPE_CLASS_TEXT -> variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
            InputType.TYPE_CLASS_NUMBER ->
                variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
            else -> false
        }
    }

    private fun isEmailInputType(inputType: Int): Boolean {
        if (inputType == 0) return false
        if (inputType and InputType.TYPE_MASK_CLASS != InputType.TYPE_CLASS_TEXT) return false
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        return variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
    }
}
