package place.atomic.app.kotlin.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.SyncProblem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import place.atomic.app.kotlin.shell.ToastController
import place.atomic.app.kotlin.shell.ToastEntry
import kotlin.math.abs
import kotlin.math.roundToInt

private val TOAST_WIDTH = 360.dp

/**
 * Draws the controller's toasts over the window without taking space or touches
 * from it: top-right on wide windows (at most 360 dp), full width minus 16 dp
 * margins on a phone. A toast goes after its time, or when swiped away
 * sideways or up; a finger on it holds the timer.
 */
@Composable
fun ToastHost(controller: ToastController, modifier: Modifier = Modifier) {
    val toasts by controller.toasts.collectAsStateWithLifecycle()
    if (toasts.isEmpty()) return
    val wide = LocalConfiguration.current.screenWidthDp >= SPLIT_FROM_DP
    Box(modifier.safeDrawingPadding().padding(top = 8.dp, start = 16.dp, end = 16.dp), contentAlignment = Alignment.TopEnd) {
        Column(
            Modifier.then(if (wide) Modifier.widthIn(max = TOAST_WIDTH) else Modifier.fillMaxWidth()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            toasts.forEach { t -> androidx.compose.runtime.key(t.key) { ToastCard(t, { controller.dismiss(t.key) }) } }
        }
    }
}

@Composable
private fun ToastCard(entry: ToastEntry, onDismiss: () -> Unit) {
    val atomic = MaterialTheme.atomic
    var held by remember { mutableStateOf(false) }
    val dismiss by rememberUpdatedState(onDismiss)
    LaunchedEffect(entry.revision, held) {
        if (!held) {
            delay(entry.durationMs)
            dismiss()
        }
    }
    var dx by remember { mutableFloatStateOf(0f) }
    var dy by remember { mutableFloatStateOf(0f) }
    val density = LocalDensity.current
    val far = with(density) { 80.dp.toPx() }
    val up = with(density) { 24.dp.toPx() }
    Surface(
        Modifier
            .offset { IntOffset(dx.roundToInt(), dy.coerceAtMost(0f).roundToInt()) }
            .alpha((1f - abs(dx) / (far * 3)).coerceIn(0.2f, 1f))
            .pointerInput(Unit) {
                awaitEachGesture {
                    awaitFirstDown(requireUnconsumed = false)
                    held = true
                    do {
                        val event = awaitPointerEvent()
                    } while (event.changes.any { it.pressed })
                    held = false
                }
            }
            .pointerInput(Unit) {
                detectDragGestures(
                    onDragEnd = {
                        if (abs(dx) > far || -dy > up) dismiss()
                        dx = 0f
                        dy = 0f
                    },
                    onDragCancel = { dx = 0f; dy = 0f },
                ) { change, drag ->
                    change.consume()
                    dx += drag.x
                    dy += drag.y
                }
            }
            .testTag("toast-${entry.key}"),
        shape = RoundedCornerShape(12.dp),
        color = atomic.bg1,
        shadowElevation = 6.dp,
    ) {
        Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Outlined.SyncProblem, contentDescription = null, Modifier.size(20.dp), tint = atomic.textSecondary)
            Text(
                entry.message,
                Modifier.weight(1f).padding(horizontal = 10.dp),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = atomic.textPrimary,
            )
            if (entry.actionLabel != null) {
                TextButton({ onDismiss(); entry.onAction?.invoke() }) { Text(entry.actionLabel) }
            }
        }
    }
}
