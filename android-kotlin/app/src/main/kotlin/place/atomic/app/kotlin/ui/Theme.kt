package place.atomic.app.kotlin.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * The colour tokens of the Atomic apps: `AppColors` of
 * `packages/atomic_flutter/lib/src/theme.dart`, which are the web app's
 * `buildTheme` tokens (main colour #1b50d8, dark: lightened). Values are
 * copied one to one so the two apps look the same.
 */
data class AtomicColors(
    val pageBg: Color,
    val panelBg: Color,
    val border: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val main: Color,
    val mainSelectedBg: Color,
    val mainSelectedFg: Color,
    val bgBody: Color,
    val bg1: Color,
    val bg2: Color,
    val alert: Color,
    val success: Color,
    val errorBg: Color,
) {
    companion object {
        val Light = AtomicColors(
            pageBg = Color(0xFFF5F5F5),
            panelBg = Color(0xFFFFFFFF),
            border = Color(0x1A000000),
            textPrimary = Color(0xFF111111),
            textSecondary = Color(0xFF666666),
            main = Color(0xFF1B50D8),
            mainSelectedBg = Color(0xFFF1F5FD),
            mainSelectedFg = Color(0xFF0E2A71),
            bgBody = Color(0xFFFAFAFA),
            bg1 = Color(0xFFF2F2F2),
            bg2 = Color(0xFFCCCCCC),
            alert = Color(0xFFCF5B5B),
            success = Color(0xFF237A42),
            errorBg = Color(0xFFFFEBEE),
        )
        val Dark = AtomicColors(
            pageBg = Color(0xFF000000),
            panelBg = Color(0xFF1A1A1A),
            border = Color(0x1AFFFFFF),
            textPrimary = Color(0xFFE5E5E5),
            textSecondary = Color(0xFFAAAAAA),
            main = Color(0xFF6C90ED),
            mainSelectedBg = Color(0xFF030817),
            mainSelectedFg = Color(0xFF7798EE),
            bgBody = Color(0xFF000000),
            bg1 = Color(0xFF1A1A1A),
            bg2 = Color(0xFF4D4D4D),
            alert = Color(0xFFCF5B5B),
            success = Color(0xFF4CC27A),
            errorBg = Color(0xFF3E0000),
        )
    }
}

val LocalAtomicColors = staticCompositionLocalOf { AtomicColors.Light }

/** The tokens of the current theme, for what Material's roles do not name. */
val MaterialTheme.atomic: AtomicColors
    @Composable get() = LocalAtomicColors.current

private fun AtomicColors.toScheme(dark: Boolean) = if (dark) {
    darkColorScheme(
        primary = main, onPrimary = Color.Black,
        primaryContainer = mainSelectedBg, onPrimaryContainer = mainSelectedFg,
        background = bgBody, onBackground = textPrimary,
        surface = bgBody, onSurface = textPrimary,
        surfaceVariant = bg1, onSurfaceVariant = textSecondary,
        surfaceContainer = bg1, surfaceContainerHigh = bg1, surfaceContainerHighest = bg1,
        outline = border, outlineVariant = border,
        error = alert, errorContainer = errorBg,
    )
} else {
    lightColorScheme(
        primary = main, onPrimary = Color.White,
        primaryContainer = mainSelectedBg, onPrimaryContainer = mainSelectedFg,
        background = bgBody, onBackground = textPrimary,
        surface = bgBody, onSurface = textPrimary,
        surfaceVariant = bg1, onSurfaceVariant = textSecondary,
        surfaceContainer = bg1, surfaceContainerHigh = bg1, surfaceContainerHighest = bg1,
        outline = border, outlineVariant = border,
        error = alert, errorContainer = errorBg,
    )
}

@Composable
fun AtomicTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val colors = if (dark) AtomicColors.Dark else AtomicColors.Light
    CompositionLocalProvider(LocalAtomicColors provides colors) {
        MaterialTheme(colorScheme = colors.toScheme(dark)) {
            // Screens without a Scaffold (first run, the secret) draw text in
            // LocalContentColor, which is black outside a Surface: near-black on
            // the dark background. The base surface sets onBackground.
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background, contentColor = MaterialTheme.colorScheme.onBackground, content = content)
        }
    }
}
