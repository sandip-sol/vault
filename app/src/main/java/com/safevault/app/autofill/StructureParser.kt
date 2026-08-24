package com.safevault.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue

/** A field on the form, with the id needed to fill it. */
data class ParsedField(
    val autofillId: AutofillId,
    val descriptor: FieldDescriptor,
    val type: FieldType,
    /** The value already in the field, when the structure carried one. */
    val value: String? = null
)

/**
 * Everything the autofill service needs to know about a request.
 *
 * [webHost] is set only when the request came from a browser and the browser
 * told us which page it is on. It is preferred over [packageName] wherever both
 * exist: a fill request from Chrome is *about* the site in the tab, and matching
 * it against `com.android.chrome` would offer every saved site's password on
 * every page.
 */
data class ParsedStructure(
    val packageName: String,
    val webHost: String,
    val fields: List<ParsedField>
) {
    val isWebRequest: Boolean get() = webHost.isNotEmpty()

    val usernameFields: List<ParsedField> get() = fields.filter { it.type == FieldType.USERNAME }

    val passwordFields: List<ParsedField>
        get() = fields.filter { it.type == FieldType.PASSWORD || it.type == FieldType.NEW_PASSWORD }

    /** True when this looks like a sign-up or change-password form. */
    val isNewCredentialForm: Boolean
        get() = fields.any { it.type == FieldType.NEW_PASSWORD } &&
            fields.none { it.type == FieldType.PASSWORD }

    val fillable: Boolean get() = FieldClassifier.isFillableForm(fields.map { it.type })

    /** Ids of every field we would fill — what a `SaveInfo` has to watch. */
    fun autofillIds(): Array<AutofillId> =
        (usernameFields + passwordFields).map { it.autofillId }.toTypedArray()
}

/**
 * Flattens an [AssistStructure] into [ParsedStructure].
 *
 * This is the only place that touches the Android view tree. Everything downstream
 * — classification, matching, dataset construction — works on plain data, which
 * is what makes the parts that decide *which credential goes where* testable off
 * a device.
 */
object StructureParser {

    /** A form deeper than this is not a login form; it is a runaway walk. */
    private const val MAX_DEPTH = 64

    /** More candidate fields than this and we are looking at a page, not a form. */
    private const val MAX_FIELDS = 100

    fun parse(structure: AssistStructure): ParsedStructure {
        val fields = mutableListOf<ParsedField>()
        var webHost = ""

        for (i in 0 until structure.windowNodeCount) {
            val root = structure.getWindowNodeAt(i).rootViewNode ?: continue
            walk(root, 0) { node ->
                if (webHost.isEmpty()) {
                    val domain = node.webDomain
                    if (!domain.isNullOrBlank()) {
                        // A page served over anything but https is not somewhere a
                        // stored password should be typed. The scheme is only
                        // readable from API 28; below that we accept the domain,
                        // because refusing every fill on older devices is worse
                        // than the risk it avoids.
                        val schemeOk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            val scheme = node.webScheme
                            scheme.isNullOrBlank() || scheme.equals("https", ignoreCase = true)
                        } else {
                            true
                        }
                        if (schemeOk) webHost = UriNormalizer.normalizeHost(domain)
                    }
                }
                if (fields.size < MAX_FIELDS) {
                    toField(node)?.let { fields += it }
                }
            }
        }

        return ParsedStructure(
            packageName = structure.activityComponent?.packageName.orEmpty(),
            webHost = webHost,
            fields = fields
        )
    }

    private fun walk(node: AssistStructure.ViewNode, depth: Int, visit: (AssistStructure.ViewNode) -> Unit) {
        if (depth > MAX_DEPTH) return
        visit(node)
        for (i in 0 until node.childCount) {
            walk(node.getChildAt(i) ?: continue, depth + 1, visit)
        }
    }

    private fun toField(node: AssistStructure.ViewNode): ParsedField? {
        val id = node.autofillId ?: return null
        // Only text fields. A list or a toggle has no credential to receive.
        if (node.autofillType != View.AUTOFILL_TYPE_TEXT) return null

        val html = node.htmlInfo
        val attrs = if (html?.tag.equals("input", ignoreCase = true)) {
            html?.attributes?.associate { it.first.lowercase() to it.second }.orEmpty()
        } else {
            emptyMap()
        }

        val descriptor = FieldDescriptor(
            hints = node.autofillHints?.toList().orEmpty(),
            idEntry = node.idEntry,
            hint = node.hint,
            htmlName = attrs["name"],
            htmlType = attrs["type"],
            htmlId = attrs["id"],
            contentDescription = node.contentDescription?.toString(),
            inputType = node.inputType,
            excluded = node.importantForAutofill == View.IMPORTANT_FOR_AUTOFILL_NO ||
                node.importantForAutofill == View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        )

        val type = FieldClassifier.classify(descriptor)
        if (type == FieldType.IGNORED) return null

        return ParsedField(
            autofillId = id,
            descriptor = descriptor,
            type = type,
            value = node.textValue()
        )
    }

    private fun AssistStructure.ViewNode.textValue(): String? {
        val value: AutofillValue? = autofillValue
        if (value != null && value.isText) return value.textValue?.toString()
        return text?.toString()
    }
}
