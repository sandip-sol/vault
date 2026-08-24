package com.safevault.app.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.core.content.getSystemService

/**
 * Copying a secret to the clipboard hands it to every app on the device, so it
 * is done deliberately and taken back quickly.
 *
 * Two mitigations, both partial by nature:
 *  - EXTRA_IS_SENSITIVE keeps the value out of the Android 13+ clipboard preview
 *    toast and out of clipboard history surfaces that honour the flag.
 *  - A timer clears the clip afterwards, but only if it is still the one we set —
 *    clearing whatever the user copied in the meantime would be its own bug.
 *
 * Neither stops a keyboard or accessibility service that reads the clipboard
 * while the value is live. Autofill is the real fix and is the next phase.
 */
object SecureClipboard {

    const val CLEAR_DELAY_MS = 30_000L

    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null

    fun copySensitive(context: Context, label: String, value: String): Boolean {
        if (value.isEmpty()) return false
        val clipboard = context.getSystemService<ClipboardManager>() ?: return false

        val clip = ClipData.newPlainText(label, value).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)
        scheduleClear(clipboard, value)
        return true
    }

    private fun scheduleClear(clipboard: ClipboardManager, copied: String) {
        pendingClear?.let(handler::removeCallbacks)
        val task = Runnable {
            if (stillHolds(clipboard, copied)) clear(clipboard)
            pendingClear = null
        }
        pendingClear = task
        handler.postDelayed(task, CLEAR_DELAY_MS)
    }

    private fun stillHolds(clipboard: ClipboardManager, copied: String): Boolean = try {
        clipboard.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)?.text?.toString() == copied
    } catch (e: Exception) {
        // Reading the clipboard can throw when the app is not foreground; assume
        // it moved on rather than clobbering someone else's clip.
        false
    }

    private fun clear(clipboard: ClipboardManager) = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    } catch (e: Exception) {
        // Best effort — a failure here must not take the app down.
    }
}
