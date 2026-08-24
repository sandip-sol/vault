package com.safevault.app.ui

import android.content.Context
import androidx.appcompat.app.AlertDialog
import androidx.core.view.isVisible
import com.safevault.app.R
import com.safevault.app.databinding.DialogPassphraseBinding

/**
 * A one-to-three field password prompt. Every flow that needs secrets typed —
 * backup passphrase, restore, master password change — shares this so the
 * validation rules and the "never echo it back" handling live in one place.
 */
object PassphraseDialog {

    data class Field(val hint: String, val prefill: String = "")

    /**
     * @param validate returns an error message for the field index it applies to,
     *   or null when the input is acceptable.
     */
    fun show(
        context: Context,
        title: String,
        note: String? = null,
        fields: List<Field>,
        positiveText: String,
        validate: (List<String>) -> Pair<Int, String>? = { null },
        onConfirm: (List<String>) -> Unit
    ) {
        val binding = DialogPassphraseBinding.inflate(android.view.LayoutInflater.from(context))
        val layouts = listOf(binding.tilOne, binding.tilTwo, binding.tilThree)
        val inputs = listOf(binding.etOne, binding.etTwo, binding.etThree)

        binding.tvNote.isVisible = note != null
        binding.tvNote.text = note

        layouts.forEachIndexed { i, layout ->
            val field = fields.getOrNull(i)
            layout.isVisible = field != null
            layout.hint = field?.hint
            inputs[i].setText(field?.prefill.orEmpty())
        }

        val dialog = AlertDialog.Builder(context)
            .setTitle(title)
            .setView(binding.root)
            .setPositiveButton(positiveText, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()

        // A stray tap outside must not silently discard a half-typed passphrase;
        // leaving is an explicit Cancel.
        dialog.setCanceledOnTouchOutside(false)

        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val values = fields.indices.map { inputs[it].text?.toString().orEmpty() }
                layouts.forEach { it.error = null }

                val error = validate(values)
                if (error != null) {
                    layouts[error.first].error = error.second
                    return@setOnClickListener
                }
                dialog.dismiss()
                onConfirm(values)
            }
        }
        dialog.show()
    }

    /** Shared rule: a backup passphrase is the only thing standing between an
     *  exported file and its contents, so it is held to the same bar as the
     *  master password. */
    fun minimumLengthError(context: Context, value: String): String? =
        if (value.length < 8) context.getString(R.string.error_password_short) else null
}
