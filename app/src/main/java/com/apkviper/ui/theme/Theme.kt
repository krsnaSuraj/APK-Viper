package com.apkviper.ui.theme

import android.app.Activity
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val Scheme = darkColorScheme(
    primary = Accent,
    onPrimary = Bg0,
    primaryContainer = AccentBg,
    onPrimaryContainer = AccentLight,
    secondary = AccentLight,
    onSecondary = Bg0,
    secondaryContainer = AccentBg,
    onSecondaryContainer = Accent,
    error = Danger,
    onError = TextPrimary,
    errorContainer = DangerBg,
    onErrorContainer = Danger,
    background = Bg0,
    onBackground = TextPrimary,
    surface = Bg1,
    onSurface = TextPrimary,
    surfaceVariant = Bg2,
    onSurfaceVariant = TextSecondary,
    outline = Border1,
    outlineVariant = Border2,
)

@Composable
fun APKViperTheme(content: @Composable () -> Unit) {
    val scheme = Scheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val activity = view.context as? Activity ?: return@SideEffect
            val window = activity.window
            window.statusBarColor = scheme.background.toArgb()
            window.navigationBarColor = scheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
        }
    }

    MaterialTheme(colorScheme = scheme, typography = ViperTypography, content = content)
}
