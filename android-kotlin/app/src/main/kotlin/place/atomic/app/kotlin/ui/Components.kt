package place.atomic.app.kotlin.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.PaddingValues

/**
 * The few pieces every screen of the account and settings side is made of:
 * one dialog style, one row, one group, one error box, one top bar. Kept few
 * on purpose; the resource lists use `ResourceRow`.
 */

/** The only dialog: a title, a body, Cancel and one action. */
@Composable
fun AtomicDialog(
    title: String,
    onDismiss: () -> Unit,
    confirmLabel: String,
    onConfirm: () -> Unit,
    confirmEnabled: Boolean = true,
    content: @Composable () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = content,
        confirmButton = { TextButton(onConfirm, enabled = confirmEnabled) { Text(confirmLabel) } },
        dismissButton = { TextButton(onDismiss) { Text("Cancel") } },
    )
}

/** A line of settings: icon, title, a second line, something at the end. */
@Composable
fun SettingsRow(
    title: String,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    subtitle: String? = null,
    trailing: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    val atomic = MaterialTheme.atomic
    Row(
        modifier
            .fillMaxWidth()
            .let { if (onClick != null) it.clickable(onClick = onClick) else it }
            .heightIn(min = if (subtitle == null) 52.dp else 64.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (icon != null) Icon(icon, contentDescription = null, tint = atomic.main, modifier = Modifier.size(24.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, maxLines = 2, overflow = TextOverflow.Ellipsis)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = atomic.textSecondary, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
        }
        trailing?.invoke()
    }
}

/** A titled card of rows. */
@Composable
fun SettingsGroup(title: String, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(modifier.padding(top = 20.dp)) {
        Text(
            title,
            Modifier.padding(start = 16.dp, bottom = 8.dp),
            color = MaterialTheme.atomic.textSecondary,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
        )
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(MaterialTheme.atomic.bg1),
        ) { content() }
    }
}

@Composable
fun ErrorBox(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(MaterialTheme.atomic.errorBg).padding(12.dp),
        color = MaterialTheme.atomic.alert,
        fontSize = 13.sp,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AtomicScaffold(
    title: String,
    onBack: () -> Unit,
    actions: @Composable RowScope.() -> Unit = {},
    snackbarHost: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = snackbarHost,
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back") }
                },
                actions = actions,
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
        content = content,
    )
}

@Composable
fun Spinner(modifier: Modifier = Modifier, size: Dp = 18.dp) {
    CircularProgressIndicator(modifier.size(size), strokeWidth = 2.dp)
}

/**
 * The one avatar of the app (Flutter's `ProfileAvatar`): the picture when the
 * File's [image] bytes are here, else the person's emoji, else their initial,
 * in a circle. The bytes are decoded at the size drawn, not at the photo's.
 */
@Composable
fun ProfileAvatar(
    name: String,
    modifier: Modifier = Modifier,
    emoji: String? = null,
    image: ByteArray? = null,
    size: Dp = 36.dp,
    background: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.primaryContainer,
    foreground: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.onPrimaryContainer,
) {
    val px = with(androidx.compose.ui.platform.LocalDensity.current) { size.roundToPx() }
    val bitmap = androidx.compose.runtime.remember(image, px) { image?.let { decodeAvatar(it, px) } }
    Box(
        modifier.size(size).clip(CircleShape).background(background),
        contentAlignment = Alignment.Center,
    ) {
        val text = emoji?.trim().orEmpty().ifEmpty { name.trim().take(1).uppercase().ifEmpty { "?" } }
        Text(text, color = foreground, fontWeight = FontWeight.SemiBold, fontSize = (size.value * 0.45f).sp)
        if (bitmap != null) {
            androidx.compose.foundation.Image(
                bitmap, contentDescription = null, Modifier.fillMaxSize(), contentScale = androidx.compose.ui.layout.ContentScale.Crop,
            )
        }
    }
}

/** [bytes] decoded no larger than [px] across, or null when they are not an image Android decodes. */
internal fun decodeAvatar(bytes: ByteArray, px: Int): androidx.compose.ui.graphics.ImageBitmap? = try {
    val bounds = android.graphics.BitmapFactory.Options().apply { inJustDecodeBounds = true }
    android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    var sample = 1
    while (bounds.outWidth / (sample * 2) >= px && bounds.outHeight / (sample * 2) >= px) sample *= 2
    val options = android.graphics.BitmapFactory.Options().apply { inSampleSize = sample }
    android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)?.asImageBitmap()
} catch (_: Exception) {
    null
}

@Composable
fun FullScreenMessage(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) { content() }
}
