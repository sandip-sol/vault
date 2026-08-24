package com.safevault.app.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.InlinePresentation
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.inline.InlinePresentationSpec
import androidx.annotation.RequiresApi
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import com.safevault.app.R
import com.safevault.app.ui.SecurityActivity

/**
 * Keyboard-strip suggestions, where the keyboard supports them (API 30+).
 *
 * Inline suggestions render in the *keyboard's* process, so like the dropdown
 * presentation they carry a title and a subtitle and never a secret. The
 * difference that matters here is that the keyboard is a third app in the
 * transaction: the vault, the form's app, and the IME. Nothing in a slice built
 * below would tell an IME anything it could not already see on the screen.
 *
 * Every entry point returns null rather than throwing when the request carries
 * no spec, the spec's style is unsupported, or the keyboard has run out of room.
 * A missing inline presentation costs a nicer UI; a thrown exception inside
 * `onFillRequest` costs the whole fill.
 */
@RequiresApi(Build.VERSION_CODES.R)
object InlinePresentations {

    /**
     * @param index which suggestion slot this is. The IME publishes one spec per
     *   slot and reuses the last one for the overflow, so asking for slot 9 of a
     *   3-slot strip is not an error.
     * @return a presentation, or null when the IME cannot show one.
     */
    fun build(
        context: Context,
        request: InlineSuggestionsRequest,
        index: Int,
        title: String,
        subtitle: String?
    ): InlinePresentation? {
        val specs = request.inlinePresentationSpecs
        if (specs.isEmpty()) return null
        if (index >= request.maxSuggestionCount) return null
        val spec: InlinePresentationSpec = specs.getOrNull(index) ?: specs.last()

        if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) {
            return null
        }

        // The content builder requires a PendingIntent for its "attribution"
        // — the thing launched if the user long-presses the chip to ask where a
        // suggestion came from. It must never be able to leak a credential, so it
        // is an immutable intent to SafeVault's security screen.
        val attribution = PendingIntent.getActivity(
            context,
            0,
            Intent(context, SecurityActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return try {
            val content = InlineSuggestionUi.newContentBuilder(attribution)
                .setTitle(title)
                .apply { if (!subtitle.isNullOrBlank()) setSubtitle(subtitle) }
                .setStartIcon(Icon.createWithResource(context, R.drawable.ic_vault))
                .build()
            InlinePresentation(content.slice, spec, /* pinned = */ false)
        } catch (e: Exception) {
            null
        }
    }
}
