package place.atomic.app.kotlin.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.draggable
import androidx.compose.foundation.gestures.rememberDraggableState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemGestures
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.MenuOpen
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.outlined.Menu
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlinx.coroutines.launch

/** How long the sidebar takes to fold away or come back. */
const val FOLD_MS = 140

/** The width of the strip along the window's left edge that opens a folded sidebar. */
private val EDGE_STRIP = 24.dp

/**
 * The tablet layout (Flutter's `_SplitPanes`): the sidebar ([list] with the
 * bottom [bar] at its foot) and the pages ([detail]) side by side. The divider
 * between them has a tab that folds the sidebar, and a strip along it that takes
 * drags: it resizes the sidebar, is a rubber band past its bounds (springing
 * back on release, closing never resisted) and folds it when pulled far left or
 * flung left. Folded, a drag from the left edge or the round button at the
 * bottom left brings it back. Both panes stay composed while it moves; the sidebar
 * keeps its width as it slides, and the pages are laid out at the width they will
 * have and clipped, so a web view is not resized on every frame.
 */
@Composable
fun SplitPanes(
    folded: Boolean,
    onFolded: (Boolean) -> Unit,
    listWidth: Float?,
    onListWidth: (Float) -> Unit,
    list: @Composable () -> Unit,
    bar: @Composable () -> Unit,
    detail: @Composable () -> Unit,
    modifier: Modifier = Modifier,
) {
    val density = LocalDensity.current
    val scope = rememberCoroutineScope()
    val atomic = MaterialTheme.atomic
    BoxWithConstraints(modifier.fillMaxSize()) {
        val room = maxWidth.value
        val full = snapPaneWidth(listPaneWidth(room, listWidth), density.density)
        val open = remember { Animatable(if (folded) 0f else 1f) }
        var dragging by remember { mutableStateOf<Float?>(null) }
        var raw by remember { mutableFloatStateOf(0f) }
        var springing by remember { mutableStateOf(false) }
        val spring = remember { Animatable(0f) }
        val hi = listPaneMax(room)
        val currentFolded by rememberUpdatedState(folded)

        LaunchedEffect(folded) { open.animateTo(if (folded) 0f else 1f, tween(FOLD_MS)) }

        fun springTo(from: Float, to: Float, velocity: Float) {
            springing = true
            scope.launch {
                spring.snapTo(from)
                spring.animateTo(to, spring(dampingRatio = 0.85f, stiffness = 260f), initialVelocity = velocity) { dragging = value }
                springing = false
                dragging = null
            }
        }

        val dragState = rememberDraggableState { deltaPx ->
            if (dragging != null && !springing) {
                raw = max(0f, raw + deltaPx / density.density)
                dragging = rubberBand(raw, 0f, hi)
            }
        }
        val onStart: () -> Unit = {
            if (springing) {
                springing = false
                scope.launch { spring.stop() }
                raw = rubberBandInverse(dragging ?: full, 0f, hi)
            } else {
                raw = if (currentFolded) 0f else full
            }
            dragging = rubberBand(raw, 0f, hi)
        }
        val onStop: (Float) -> Unit = stop@{ velocityPx ->
            val w = dragging ?: return@stop
            if (springing) return@stop
            val velocity = velocityPx / density.density
            val slope = rubberBandSlope(raw, 0f, hi)
            scope.launch {
                when (dragEnd(currentFolded, w, raw, full, velocity)) {
                    DragEnd.Open -> {
                        onFolded(false)
                        open.snapTo((w / full).coerceIn(0f, 1f))
                        if (w > full + 0.5f) {
                            open.snapTo(1f)
                            springTo(w, full, velocity * slope)
                        } else {
                            dragging = null
                            open.animateTo(1f, tween(FOLD_MS))
                        }
                    }
                    DragEnd.BackToFolded -> {
                        open.snapTo((w / full).coerceIn(0f, 1f))
                        dragging = null
                        open.animateTo(0f, tween(FOLD_MS))
                    }
                    DragEnd.Fold -> {
                        open.snapTo((w / full).coerceIn(0f, 1f))
                        dragging = null
                        onFolded(true)
                    }
                    DragEnd.Settle -> {
                        val settled = listPaneWidth(room, w)
                        onListWidth(settled)
                        open.snapTo(1f)
                        onFolded(false)
                        if (abs(w - settled) > 0.5f) springTo(w, settled, velocity * slope) else dragging = null
                    }
                }
            }
        }
        val drag = Modifier.draggable(
            dragState,
            Orientation.Horizontal,
            onDragStarted = { onStart() },
            onDragStopped = { onStop(it) },
        )

        val shown = snapPaneWidth(dragging ?: (full * open.value), density.density)
        val gone = shown <= 0.5f
        val listFull = if (dragging == null) full else max(MIN_LIST_DP, min(dragging!!, room - MIN_DETAIL_DP))
        val resizing = dragging != null && !folded
        val detailWidth = if (resizing) (room - shown - 1) else if (folded) room else room - full - 1

        Box(Modifier.fillMaxSize()) {
            androidx.compose.foundation.layout.Row(Modifier.fillMaxSize()) {
                // The sidebar keeps its width while it slides away: no row is laid out again on every frame.
                Box(Modifier.width(shown.dp).fillMaxHeight().clipToBounds().testTag("sidebar")) {
                    Column(
                        Modifier.wrapContentWidth(Alignment.End, unbounded = true).requiredWidth(listFull.dp).fillMaxHeight(),
                    ) {
                        Box(Modifier.weight(1f)) { list() }
                        bar()
                    }
                }
                if (!gone) Box(Modifier.width(1.dp).fillMaxHeight().background(MaterialTheme.colorScheme.outlineVariant))
                Box(Modifier.weight(1f).fillMaxHeight().clipToBounds()) {
                    // Laid out at the width it will have once the sidebar has moved, and clipped to what shows.
                    Box(Modifier.wrapContentWidth(Alignment.Start, unbounded = true).requiredWidth(detailWidth.dp).fillMaxHeight()) { detail() }
                }
            }
            if (!folded) {
                // A strip along the whole divider takes drags.
                Box(Modifier.offset(x = (shown - 8f).dp).width(16.dp).fillMaxHeight().then(drag).testTag("divider-strip"))
                // The tab on the line: a tap folds the sidebar (a 48 x 64 target).
                Box(
                    Modifier.offset(x = (shown - 24f).dp).width(48.dp).height(64.dp).align(Alignment.CenterStart)
                        .then(drag).clickable(onClickLabel = "Hide list") { onFolded(true) }.testTag("list-toggle"),
                    contentAlignment = Alignment.Center,
                ) {
                    Surface(
                        Modifier.size(24.dp, 48.dp),
                        shape = RoundedCornerShape(12.dp),
                        color = atomic.bg1,
                        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    ) {
                        Icon(Icons.Filled.ChevronLeft, contentDescription = "Hide list", Modifier.padding(3.dp), tint = atomic.textSecondary)
                    }
                }
            } else {
                // A strip along the window's left edge opens the sidebar with one drag that follows the finger.
                // It starts beyond the system gesture inset (Android's back swipe owns the very edge) and is
                // opaque, so the web view under it never sees the swipe.
                val gestureLeft = with(density) { WindowInsets.systemGestures.getLeft(density, androidx.compose.ui.unit.LayoutDirection.Ltr).toDp() }
                Box(Modifier.offset(x = gestureLeft).width(EDGE_STRIP).fillMaxHeight().then(drag).testTag("edge-strip"))
                val bottom = with(density) { WindowInsets.navigationBars.getBottom(density).toDp() }
                Surface(
                    Modifier.align(Alignment.BottomStart).padding(start = 8.dp, bottom = 8.dp + bottom).testTag("list-toggle"),
                    shape = CircleShape,
                    color = atomic.bg1,
                    shadowElevation = 2.dp,
                ) {
                    IconButton(onClick = { onFolded(false) }) { Icon(Icons.Outlined.Menu, contentDescription = "Show list") }
                }
            }
        }
    }
}

/** The "Close sidebar" icon of the bar. */
val CloseSidebarIcon get() = Icons.AutoMirrored.Outlined.MenuOpen
