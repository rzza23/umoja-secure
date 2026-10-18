package com.umoja.secure.ui.common

import android.app.Activity
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalView

/**
 * Set `WindowManager.LayoutParams.FLAG_SECURE` for the lifetime of this
 * composition.
 *
 * FLAG_SECURE blocks:
 *   - Android screenshot capture (screencap, Power + Volume-Down)
 *   - The app appearing in the Recents thumbnail
 *   - Screen recording by system services
 *
 * Cleared in [DisposableEffect.onDispose] so navigating out of the
 * screen releases the flag.
 *
 * **Safe for current app shape**: at most one `SecureScreen`-using
 * composable is composed at a time. `AppScreen` is a single state;
 * `ChatScreen` replaces the tab shell rather than stacking, and
 * `AdminScreen` / `DiagnosticsScreen` are top-level `AppScreen`
 * routes. If a future change stacks multiple `SecureScreen` calls,
 * the flag would need a reference count — the current unconditional
 * clear-on-dispose would unset the flag while a parent is still on
 * screen. Recorded here so that future change sees the assumption.
 *
 * **Scope per ADR-HARDENING-001 §3**: `ChatScreen`, `AdminScreen`,
 * `DiagnosticsScreen`. The ADR explicitly excludes the enrollment
 * screen (user-entered token is short-lived, QR payload is public
 * device keys) and settings (role + logout only). A full UI audit
 * (this commit's message) confirmed the ADR's proposal was complete.
 *
 * The cast `LocalView.current.context as? Activity` is safe in this
 * app: every screen is hosted inside `MainActivity`'s `setContent`
 * tree, and `LocalView` is the Android View backing the composition.
 * A null activity is a silent no-op — FLAG_SECURE is defence-in-depth
 * at the composition level, not a hard requirement.
 */
@Composable
fun SecureScreen() {
    val view = LocalView.current
    val activity = view.context as? Activity
    DisposableEffect(activity) {
        activity?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            activity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
