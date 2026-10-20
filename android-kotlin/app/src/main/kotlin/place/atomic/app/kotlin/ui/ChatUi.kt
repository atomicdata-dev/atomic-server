package place.atomic.app.kotlin.ui

import androidx.compose.foundation.background
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.scrollBy
import androidx.compose.foundation.interaction.DragInteraction
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.outlined.KeyboardArrowDown
import androidx.compose.material.icons.outlined.KeyboardDoubleArrowDown
import androidx.compose.material3.Surface
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.IntOffset
import kotlin.math.roundToInt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material.icons.outlined.Stop
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

/** How many items from either end a page is read (Flutter's `ChatScrollKeeper.edge`). */
private const val EDGE = 15

/** Within this many pixels of the bottom counts as at the bottom. */
private const val BOTTOM_SLACK_PX = 80

val LazyListState.atBottom: Boolean
    get() = firstVisibleItemIndex == 0 && firstVisibleItemScrollOffset <= BOTTOM_SLACK_PX

/** What a chat list asks of its window as the person scrolls. */
class ChatListActions(
    val loadOlder: () -> Unit,
    val loadNewer: () -> Unit,
    val trimOldest: () -> Unit,
    val trimNewest: () -> Unit,
    val jumpToLatest: () -> Unit,
    /** The window holds at most this many items. */
    val maxHeld: Int,
)

/**
 * A chat list over a window: newest at the bottom (`reverseLayout`, so index 0
 * is the newest), a day separator above the first message of a day, older pages
 * read within [EDGE] items of the top, newer ones near the bottom while the
 * window is detached, the window kept bounded, and a "Jump to latest" button
 * once scrolled up by more than a screen or when news waits. Twin of Flutter's
 * `ChatScrollKeeper` and its list.
 */
@Composable
fun <T> ChatList(
    items: List<T>,
    key: (T) -> String,
    createdAt: (T) -> Long,
    hasOlder: Boolean,
    detached: Boolean,
    unseen: Int,
    actions: ChatListActions,
    modifier: Modifier = Modifier,
    state: LazyListState = rememberLazyListState(),
    /** An answer streams in at the end of [items]: see [FollowAnswer]. */
    followAnswer: Boolean = false,
    row: @Composable (index: Int, item: T) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val density = androidx.compose.ui.platform.LocalDensity.current
    val follow = rememberFollowAnswer(state, followAnswer, items.lastOrNull()?.let(key), items.getOrNull(items.size - 2)?.let(key))
    val count = items.size
    val total by rememberUpdatedState(count)
    val onActions by rememberUpdatedState(actions)
    // The top: older messages are read when the eye is within EDGE items of it.
    LaunchedEffect(state, hasOlder) {
        snapshotFlow { state.firstVisibleItemIndex + state.layoutInfo.visibleItemsInfo.size }
            .distinctUntilChanged()
            .collect { seen -> if (hasOlder && total - seen <= EDGE) onActions.loadOlder() }
    }
    // The bottom: back towards the newest while detached, else the oldest pages go.
    LaunchedEffect(state, detached) {
        snapshotFlow { state.firstVisibleItemIndex to state.atBottom }
            .distinctUntilChanged()
            .collect { (first, bottom) ->
                if (bottom) {
                    if (detached) onActions.loadNewer() else onActions.trimOldest()
                } else if (first > onActions.maxHeld / 2 + EDGE) {
                    onActions.trimNewest()
                }
            }
    }
    // A message that arrives (or is sent) while at the bottom stays in view.
    val newest = items.lastOrNull()?.let(key)
    LaunchedEffect(newest) { if (state.firstVisibleItemIndex <= 1) state.animateScrollToItem(0) }

    val far by remember(state) { derivedStateOf { state.firstVisibleItemIndex > state.layoutInfo.visibleItemsInfo.size } }
    Box(modifier) {
        LazyColumn(
            state = state,
            reverseLayout = true,
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        ) {
            // Room below the answer, so the question can sit at the top with the answer growing under it.
            if (follow.spacerPx > 0) item(key = "follow-spacer") { Spacer(Modifier.height(with(density) { follow.spacerPx.toDp() })) }
            items(count, key = { key(items[count - 1 - it]) }) { i ->
                val index = count - 1 - i
                val item = items[index]
                val newDay = createdAt(item) > 0 && (
                    (index == 0 && !hasOlder) ||
                        (index > 0 && createdAt(items[index - 1]) > 0 && otherDay(createdAt(items[index - 1]), createdAt(item)))
                    )
                Column {
                    if (newDay) DaySeparator(dayLabel(createdAt(item)))
                    row(index, item)
                }
            }
            if (hasOlder) {
                item(key = "older") {
                    Box(Modifier.fillMaxWidth().padding(12.dp), contentAlignment = Alignment.Center) { Spinner(size = 16.dp) }
                }
            }
        }
        ScrollToBottomButton(
            wanted = unseen > 0 || detached || far,
            far = detached || far,
            unseen = unseen,
            modifier = Modifier.align(Alignment.BottomEnd).padding(12.dp),
        ) {
            actions.jumpToLatest()
            scope.launch { state.scrollToItem(0) }
        }
    }
}

/**
 * Following an answer as it streams in (Flutter's `_settle`): the question sits
 * at the top of the list with the answer growing under it ([spacerPx] is the room
 * below); the list follows the growing answer at the bottom while the answer's top
 * is in view; once the answer fills the screen its top is held there, so it can be
 * read from its start. A person who drags the list takes over. Layout-driven, so it
 * settles after every change of the sizes it watches.
 */
class FollowAnswer {
    var spacerPx by mutableIntStateOf(0)
    var following by mutableStateOf(false)
    var pinned by mutableStateOf(false)
}

/** The smallest gap kept between the question and the top of the list. */
private const val FOLLOW_GAP_PX = 32

@Composable
private fun rememberFollowAnswer(state: LazyListState, active: Boolean, answerKey: String?, questionKey: String?): FollowAnswer {
    val follow = remember { FollowAnswer() }
    val answer by rememberUpdatedState(answerKey)
    val question by rememberUpdatedState(questionKey)
    LaunchedEffect(state) {
        state.interactionSource.interactions.collect { if (it is DragInteraction.Start) follow.following = false }
    }
    LaunchedEffect(active) {
        if (!active) return@LaunchedEffect
        follow.spacerPx = 0
        follow.following = true
        follow.pinned = false
        var lastAnswer = -1
        snapshotFlow {
            val info = state.layoutInfo
            val items = info.visibleItemsInfo
            listOf(
                items.firstOrNull { it.key == answer }?.size ?: -1,
                items.firstOrNull { it.key == question }?.size ?: -1,
                info.viewportEndOffset - info.viewportStartOffset,
                follow.spacerPx,
            )
        }.distinctUntilChanged().collect {
            if (!follow.following) return@collect
            val info = state.layoutInfo
            val items = info.visibleItemsInfo
            val a = items.firstOrNull { it.key == answer } ?: return@collect
            val q = items.firstOrNull { it.key == question }
            val viewport = info.viewportEndOffset - info.viewportStartOffset - info.beforeContentPadding - info.afterContentPadding
            val grew = if (lastAnswer < 0) 0 else a.size - lastAnswer
            lastAnswer = a.size
            if (!follow.pinned) {
                if (q != null && state.firstVisibleItemIndex <= 1) {
                    val want = maxOf(0, viewport - FOLLOW_GAP_PX - (q.size + a.size))
                    if (kotlin.math.abs(want - follow.spacerPx) > 1) {
                        follow.spacerPx = want
                        return@collect
                    }
                }
                // The answer's top has reached the top of the list: hold it there.
                if (a.offset + a.size >= info.viewportEndOffset - info.afterContentPadding - 1) follow.pinned = true
            } else if (grew > 0) {
                state.scrollBy(grew.toFloat())
            }
        }
    }
    return follow
}

/**
 * The one "back to the newest message" button of every chat list (Flutter's
 * `ScrollToBottomButton`): a small round button at the bottom right over the
 * list, shown only while the list is not at the bottom. It scales and fades in
 * with a little overshoot, hops once (also when a new message comes in while it
 * shows), has a double arrow when the newest is further than a screen away, counts
 * [unseen] messages on a badge, and shrinks away when the list reaches the bottom.
 */
@Composable
fun ScrollToBottomButton(wanted: Boolean, far: Boolean, unseen: Int, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val show = remember { Animatable(if (wanted) 1f else 0f) }
    val hop = remember { Animatable(0f) }
    val lastUnseen = remember { mutableIntStateOf(unseen) }
    LaunchedEffect(wanted) {
        if (wanted) {
            launch { hop.snapTo(0f); hop.animateTo(1f, tween(520)) }
            show.animateTo(1f, spring(dampingRatio = 0.5f, stiffness = 600f))
        } else {
            show.animateTo(0f, tween(140))
        }
    }
    LaunchedEffect(unseen) {
        if (unseen > lastUnseen.intValue && wanted) {
            hop.snapTo(0f)
            hop.animateTo(1f, tween(520))
        }
        lastUnseen.intValue = unseen
    }
    if (show.value <= 0.01f && !wanted) return
    val haptic = LocalHapticFeedback.current
    val atomic = MaterialTheme.colorScheme
    val label = if (unseen > 0) "$unseen new messages" else "Scroll to newest"
    // 48 dp to hit, 40 dp to see.
    Box(
        modifier
            .size(48.dp)
            .graphicsLayer { scaleX = show.value; scaleY = show.value; alpha = show.value.coerceIn(0f, 1f) }
            .semantics { contentDescription = label }
            .clickable(enabled = wanted, role = Role.Button) { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onClick() }
            .testTag("scroll-to-bottom"),
        contentAlignment = Alignment.Center,
    ) {
        BadgedBox(badge = { if (unseen > 0) Badge { Text(if (unseen > 99) "99+" else "$unseen") } }) {
            Surface(Modifier.size(40.dp), shape = CircleShape, color = atomic.primaryContainer, shadowElevation = 2.dp) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        if (far) Icons.Outlined.KeyboardDoubleArrowDown else Icons.Outlined.KeyboardArrowDown,
                        contentDescription = null,
                        Modifier.size(22.dp).offset { IntOffset(0, (3.dp.toPx() * hopCurve(hop.value)).roundToInt()) },
                        tint = atomic.onPrimaryContainer,
                    )
                }
            }
        }
    }
}

/** 0 -> 1 -> 0 over the hop. */
internal fun hopCurve(t: Float): Float = if (t <= 0f || t >= 1f) 0f else if (t < 0.4f) t / 0.4f else (1f - t) / 0.6f

/** A day separator line. */
@Composable
fun DaySeparator(label: String) {
    Box(Modifier.fillMaxWidth().padding(vertical = 10.dp), contentAlignment = Alignment.Center) {
        Text(label, color = MaterialTheme.atomic.textSecondary, fontSize = 12.sp, modifier = Modifier.testTag("day-separator"))
    }
}

/** A message bubble: mine in the selected colours on the right, the others' on the left. */
@Composable
fun Bubble(mine: Boolean, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val atomic = MaterialTheme.atomic
    Box(
        modifier
            .clip(RoundedCornerShape(9.dp))
            .background(if (mine) atomic.mainSelectedBg else atomic.bg1)
            .padding(horizontal = 14.dp, vertical = 10.dp),
    ) { content() }
}

/**
 * The field to write a message in: the keyboard's send key sends, the arrow
 * button too (greyed while there is nothing to send), and while a reply streams
 * the button is a Stop. The field stays enabled while a reply streams (a second
 * send is ignored), so the keyboard stays open for the next message.
 */
@Composable
fun Composer(
    value: String,
    onValueChange: (String) -> Unit,
    onSend: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    sending: Boolean = false,
    onStop: (() -> Unit)? = null,
    error: String? = null,
    chips: (@Composable () -> Unit)? = null,
    leading: (@Composable () -> Unit)? = null,
) {
    val atomic = MaterialTheme.atomic
    Column(modifier.fillMaxWidth().navigationBarsPadding().imePadding().padding(start = 12.dp, top = 4.dp, end = 12.dp, bottom = 12.dp)) {
        if (error != null) {
            Text(error, Modifier.padding(bottom = 6.dp), color = atomic.alert, fontSize = 12.sp)
        }
        if (chips != null) chips()
        Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            if (leading != null) leading()
            OutlinedTextField(
                value = value,
                onValueChange = onValueChange,
                modifier = Modifier.weight(1f).testTag("message-field"),
                enabled = enabled,
                placeholder = { Text("Message") },
                minLines = 1,
                maxLines = 5,
                shape = RoundedCornerShape(9.dp),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                keyboardActions = KeyboardActions(onSend = { if (value.isNotBlank()) onSend() }),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = atomic.bg1,
                    unfocusedContainerColor = atomic.bg1,
                    disabledContainerColor = atomic.bg1,
                    focusedBorderColor = androidx.compose.ui.graphics.Color.Transparent,
                    unfocusedBorderColor = androidx.compose.ui.graphics.Color.Transparent,
                    disabledBorderColor = androidx.compose.ui.graphics.Color.Transparent,
                ),
            )
            if (sending && onStop != null) {
                FilledIconButton(onStop, Modifier.size(48.dp).testTag("chat-stop")) {
                    Icon(Icons.Outlined.Stop, contentDescription = "Stop")
                }
            } else {
                FilledIconButton(onSend, Modifier.size(48.dp).testTag("chat-send"), enabled = enabled && value.isNotBlank()) {
                    Icon(Icons.Outlined.ArrowUpward, contentDescription = "Send")
                }
            }
        }
    }
}
