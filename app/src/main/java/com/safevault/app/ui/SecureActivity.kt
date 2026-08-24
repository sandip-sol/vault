package com.safevault.app.ui

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import com.safevault.app.security.SessionManager

/**
 * Shared behaviour for every screen that can display vault contents:
 * screenshots are blocked, and the screen refuses to exist while the vault is
 * locked. The auto-lock decision itself belongs to
 * [com.safevault.app.SafeVaultApp]; this only reacts to its outcome, so a
 * timeout that fires in the background lands on whichever screen resumes.
 */
abstract class SecureActivity : AppCompatActivity() {

    /** Screens shown before unlock (the unlock screen itself) opt out. */
    protected open val requiresUnlockedVault: Boolean = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        if (requiresUnlockedVault && !SessionManager.isUnlocked) {
            returnToUnlock()
        }
    }

    override fun onResume() {
        super.onResume()
        if (requiresUnlockedVault && !SessionManager.isUnlocked) {
            returnToUnlock()
        }
    }

    /** Clears the session and sends the user back to the unlock screen. */
    protected fun lockVault() {
        SessionManager.lock()
        returnToUnlock()
    }

    private fun returnToUnlock() {
        if (isFinishing) return
        startActivity(
            Intent(this, UnlockActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        )
        finish()
    }
}
