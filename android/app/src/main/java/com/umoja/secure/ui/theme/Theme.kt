package com.umoja.secure.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// Note: we ignore isSystemInDarkTheme for the default because Umoja is
// dark-first. Users can opt in to light theme in Settings later; until
// then the app is always dark, which is also the visual identity.
private val UmojaDark = darkColorScheme(
    primary = Primary,
    onPrimary = OnPrimary,
    primaryContainer = PrimaryContainerDark,
    onPrimaryContainer = OnPrimaryContainer,
    background = BackgroundDark,
    onBackground = OnBackgroundDark,
    surface = SurfaceDark,
    onSurface = OnBackgroundDark,
    surfaceVariant = SurfaceVariantDark,
    onSurfaceVariant = OnSurfaceVariantDark,
    outline = OutlineDark,
    error = Danger,
    onError = OnPrimary,
)

private val UmojaLight = lightColorScheme(
    primary = PrimaryVariant,
    onPrimary = OnPrimary,
    primaryContainer = PrimaryContainerLight,
    onPrimaryContainer = OnPrimaryContainerLight,
    background = BackgroundLight,
    onBackground = OnBackgroundLight,
    surface = SurfaceLight,
    onSurface = OnBackgroundLight,
    surfaceVariant = SurfaceVariantLight,
    onSurfaceVariant = OnSurfaceVariantLight,
    outline = OutlineLight,
    error = Danger,
    onError = OnPrimary,
)

@Composable
fun UmojaSecureTheme(
    useLightTheme: Boolean = false,
    content: @Composable () -> Unit,
) {
    val colorScheme = if (useLightTheme) UmojaLight else UmojaDark

    // Make the status bar and navigation bar match the background so
    // there's no visible seam at the top and bottom of the screen.
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            window.navigationBarColor = colorScheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars =
                useLightTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = UmojaTypography,
        shapes = UmojaShapes,
        content = content,
    )
}
