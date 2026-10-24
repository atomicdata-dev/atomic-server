package place.atomic.app.kotlin.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.changedToUpIgnoreConsumed
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.LayoutCoordinates
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntRect
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupPositionProvider
import androidx.compose.ui.window.PopupProperties
import androidx.compose.ui.text.style.TextOverflow
import kotlinx.coroutines.withTimeoutOrNull

/** How long a still finger waits before the menu opens, and how far a finger moves for a swipe. */
const val HOLD_DELAY_MS = 150L
val HOLD_SWIPE_SLOP = 8.dp

/** One choice of a [HoldMenu]: a label led by an emoji or an icon. */
data class HoldItem<T>(val label: String, val value: T, val icon: ImageVector? = null, val emoji: String? = null)

/**
 * The bottom bar's gesture, one for Home, Search and New (Flutter's
 * `HoldFan.opensOnDown`): the menu opens at once when the finger moves more
 * than [HOLD_SWIPE_SLOP] (a swipe) or after [HOLD_DELAY_MS] of a finger held
 * still. Then the finger drags through the rows (the one under it marked) and
 * letting go picks one, or, off the rows, closes the menu; letting go without
 * having moved leaves it open for a tap on a row. A lift before the swipe or
 * the delay is a tap: it does [onTap], or opens the menu when [tapOpensMenu].
 */
@Composable
fun <T> HoldMenu(
    items: List<HoldItem<T>>,
    onSelected: (T) -> Unit,
    modifier: Modifier = Modifier,
    onTap: (() -> Unit)? = null,
    tapOpensMenu: Boolean = false,
    onOpen: () -> Unit = {},
    /** For tests and screenshots: the menu starts open. */
    startOpen: Boolean = false,
    content: @Composable () -> Unit,
) {
    var open by remember { mutableStateOf(startOpen) }
    var marked by remember { mutableIntStateOf(-1) }
    var buttonBounds by remember { mutableStateOf(Rect.Zero) }
    val rows = remember { mutableMapOf<Int, Rect>() }
    val slop = with(LocalDensity.current) { HOLD_SWIPE_SLOP.toPx() }
    val haptic = LocalHapticFeedback.current
    val items by rememberUpdatedState(items)
    val onTapNow by rememberUpdatedState(onTap)
    val onSelectedNow by rememberUpdatedState(onSelected)
    val onOpenNow by rememberUpdatedState(onOpen)

    fun rowAt(p: Offset): Int = rows.entries.firstOrNull { it.value.contains(p) }?.key ?: -1

    Box(
        modifier
            .onGloballyPositioned { buttonBounds = it.boundsInWindow() }
            .pointerInput(tapOpensMenu) {
                awaitEachGesture {
                    val down = awaitFirstDown(requireUnconsumed = false)
                    val origin = down.position
                    var moved = false
                    var opened = false
                    // Window position of the finger.
                    fun window(local: Offset) = local + buttonBounds.topLeft
                    // Wait for a swipe or the hold delay; a lift before is a tap.
                    val tap = withTimeoutOrNull(HOLD_DELAY_MS) {
                        while (true) {
                            val event = awaitPointerEvent(PointerEventPass.Initial)
                            val change = event.changes.firstOrNull { it.id == down.id } ?: return@withTimeoutOrNull false
                            if (change.changedToUpIgnoreConsumed()) return@withTimeoutOrNull true
                            if ((change.position - origin).getDistance() > slop) {
                                moved = true
                                return@withTimeoutOrNull false
                            }
                        }
                    }
                    if (tap == true) {
                        down.consume()
                        if (tapOpensMenu) {
                            onOpenNow()
                            open = true
                        } else {
                            onTapNow?.invoke()
                        }
                        return@awaitEachGesture
                    }
                    // Swipe or hold: the menu is open while the finger drags.
                    opened = true
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onOpenNow()
                    marked = -1
                    open = true
                    while (true) {
                        val event = awaitPointerEvent(PointerEventPass.Initial)
                        val change = event.changes.firstOrNull { it.id == down.id } ?: break
                        change.consume()
                        if ((change.position - origin).getDistance() > slop) moved = true
                        val row = rowAt(window(change.position))
                        if (row != marked) {
                            marked = row
                            if (row >= 0) haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        }
                        if (change.changedToUpIgnoreConsumed()) {
                            val pick = if (moved) rowAt(window(change.position)) else -1
                            if (moved) {
                                open = false
                                if (pick >= 0) items.getOrNull(pick)?.let { onSelectedNow(it.value) }
                            }
                            // A finger that never moved leaves the menu open for a tap.
                            marked = -1
                            break
                        }
                    }
                    if (opened && !open) rows.clear()
                }
            }
            .testTag("hold-menu"),
        contentAlignment = Alignment.Center,
    ) {
        content()
        if (open) {
            Popup(
                popupPositionProvider = remember { AboveAnchor },
                onDismissRequest = { open = false; marked = -1 },
                properties = PopupProperties(focusable = false, dismissOnClickOutside = true),
            ) {
                MenuCard(items, marked, rows) { value ->
                    open = false
                    marked = -1
                    onSelectedNow(value)
                }
            }
        }
    }
}

/** The menu stacked straight above the button, inside the window (below it with no room above). */
private object AboveAnchor : PopupPositionProvider {
    override fun calculatePosition(anchorBounds: IntRect, windowSize: IntSize, layoutDirection: LayoutDirection, popupContentSize: IntSize): IntOffset {
        val x = (anchorBounds.center.x - popupContentSize.width / 2).coerceIn(8, (windowSize.width - popupContentSize.width - 8).coerceAtLeast(8))
        val above = anchorBounds.top - popupContentSize.height - 8
        val y = if (above >= 8) above else (anchorBounds.bottom + 8).coerceAtMost((windowSize.height - popupContentSize.height).coerceAtLeast(0))
        return IntOffset(x, y)
    }
}

@Composable
private fun <T> MenuCard(items: List<HoldItem<T>>, marked: Int, rows: MutableMap<Int, Rect>, onPick: (T) -> Unit) {
    val atomic = MaterialTheme.atomic
    Surface(shape = RoundedCornerShape(16.dp), color = atomic.bg1, shadowElevation = 12.dp, modifier = Modifier.testTag("hold-menu-card")) {
        Column(Modifier.widthIn(min = 180.dp, max = 280.dp).padding(vertical = 8.dp)) {
            items.forEachIndexed { index, item ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .onGloballyPositioned { rows[index] = it.boundsInWindow() }
                        .background(if (index == marked) atomic.mainSelectedBg else androidx.compose.ui.graphics.Color.Transparent)
                        .clickable { onPick(item.value) }
                        .padding(horizontal = 16.dp)
                        .testTag("hold-item-${item.label}"),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Box(Modifier.size(24.dp), contentAlignment = Alignment.Center) {
                        when {
                            item.emoji != null -> Text(item.emoji, fontSize = 18.sp)
                            item.icon != null -> Icon(item.icon, contentDescription = null, tint = atomic.textSecondary)
                        }
                    }
                    Text(item.label, maxLines = 1, overflow = TextOverflow.Ellipsis, color = if (index == marked) atomic.mainSelectedFg else atomic.textPrimary)
                }
            }
        }
    }
}
