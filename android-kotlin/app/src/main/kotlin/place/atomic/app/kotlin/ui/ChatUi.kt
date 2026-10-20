package place.atomic.app.kotlin.ui

import androidx.compose.foundation.background
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
import androidx.compose.material.icons.outlined.ArrowDownward
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material.icons.outlined.Stop
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.SmallFloatingActionButton
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
    row: @Composable (index: Int, item: T) -> Unit,
) {
    val scope = rememberCoroutineScope()
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
        if (far || unseen > 0) {
            JumpToLatest(
                unseen,
                Modifier.align(Alignment.BottomEnd).padding(12.dp),
            ) {
                actions.jumpToLatest()
                scope.launch { state.scrollToItem(0) }
            }
        }
    }
}

@Composable
fun JumpToLatest(unseen: Int, modifier: Modifier = Modifier, onClick: () -> Unit) {
    SmallFloatingActionButton(onClick, modifier.testTag("jump-to-latest")) {
        if (unseen > 0) {
            BadgedBox(badge = { Badge { Text(if (unseen > 99) "99+" else "$unseen") } }) {
                Icon(Icons.Outlined.ArrowDownward, contentDescription = "$unseen new")
            }
        } else {
            Icon(Icons.Outlined.ArrowDownward, contentDescription = "Jump to latest")
        }
    }
}

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
