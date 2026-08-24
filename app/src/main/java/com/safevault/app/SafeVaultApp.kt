package com.safevault.app

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.safevault.app.security.SessionManager
import com.safevault.app.security.VaultPrefs

/**
 * Owns the auto-lock clock for the whole process.
 *
 * Previously each activity timed its own onPause/onResume, which meant opening
 * the entry editor looked like leaving the app, and a screen that was not
 * resumed never checked at all. Watching the process lifecycle instead gives one
 * definition of "the user left": the last activity stopped.
 */
class SafeVaultApp : Application(), DefaultLifecycleObserver {

    override fun onCreate() {
        super<Application>.onCreate()
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    override fun onStop(owner: LifecycleOwner) {
        SessionManager.onEnterBackground()
    }

    override fun onStart(owner: LifecycleOwner) {
        SessionManager.onEnterForeground(VaultPrefs(this).autoLockMs)
    }
}
