package place.atomic.app.kotlin.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.EditNote
import androidx.compose.material.icons.outlined.NearMe
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.chat.NativeKind
import place.atomic.app.kotlin.chat.ThreadState
import place.atomic.app.kotlin.core.ThreadMessage

/** What a conversation or chat-room screen asks of its model and its host. */
class ThreadActions(
    val onBack: () -> Unit,
    val onSend: (String) -> Unit,
    val list: ChatListActions,
    /** A "Viewing" line of a meeting opens the resource it is about. */
    val onOpenAbout: (subject: String, title: String) -> Unit = { _, _ -> },
    /** Rooms only: the new name. */
    val onRename: (String) -> Unit = {},
    val onUnsentTaken: () -> Unit = {},
    val onPainted: () -> Unit = {},
)

/** Messages of one author closer together than this are one group: the author is named once above it and the time shown once below it. */
private const val GROUP_GAP_MS = 5 * 60_000L

/**
 * The chat of a conversation (DM or group, end-to-end encrypted and opened on
 * this device), a meeting or a chat room: bubbles, mine on the right and the
 * others' on the left, newest at the bottom, the meeting's events as compact
 * lines, and a field to write one. Twin of Flutter's `ConversationScreen` and
 * `ChatRoomScreen`.
 */
@Composable
fun ThreadScreen(kind: NativeKind, state: ThreadState, actions: ThreadActions) {
    var input by rememberSaveable { mutableStateOf("") }
    var renaming by remember { mutableStateOf(false) }
    val room = kind == NativeKind.Room
    LaunchedEffect(state.window.loaded) {
        if (state.window.loaded) {
            withFrameNanos { }
            actions.onPainted()
        }
    }
    // A message that could not be sent comes back into the field.
    LaunchedEffect(state.unsent) {
        val unsent = state.unsent
        if (unsent != null) {
            if (input.isEmpty()) input = unsent
            actions.onUnsentTaken()
        }
    }
    val title = if (room) state.title.ifEmpty { "Chat" } else state.title.ifEmpty { "Conversation" }
    AtomicScaffold(
        title = title,
        onBack = actions.onBack,
        actions = {
            if (room) {
                IconButton({ renaming = true }, Modifier.testTag("rename")) { Icon(Icons.Outlined.EditNote, contentDescription = "Rename") }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            Box(Modifier.weight(1f).fillMaxWidth()) { Messages(room, state, actions) }
            Composer(input, { input = it }, { actions.onSend(input); input = "" }, error = state.error)
        }
    }
    if (renaming) {
        var name by remember { mutableStateOf(TextFieldValue(title, TextRange(0, title.length))) }
        AtomicDialog(
            title = "Rename chat",
            onDismiss = { renaming = false },
            confirmLabel = "Save",
            onConfirm = { actions.onRename(name.text); renaming = false },
        ) {
            // All selected: typing replaces the old name ("ChatRoom" on a new room).
            OutlinedTextField(name, { name = it }, Modifier.testTag("chat-room-name"), singleLine = true)
        }
    }
}

@Composable
private fun Messages(room: Boolean, state: ThreadState, actions: ThreadActions) {
    val atomic = MaterialTheme.atomic
    val error = state.window.error
    if (error != null) {
        Box(Modifier.fillMaxSize().padding(24.dp), Alignment.Center) { Text(error, color = atomic.alert, textAlign = TextAlign.Center) }
        return
    }
    if (!state.window.loaded) {
        Box(Modifier.fillMaxSize(), Alignment.Center) { Spinner(size = 32.dp) }
        return
    }
    val shown = state.shown
    if (shown.isEmpty()) {
        Box(Modifier.fillMaxSize(), Alignment.Center) { Text("No messages yet", color = atomic.textSecondary, fontSize = 13.sp) }
        return
    }
    // Others' names show when more than one other person has spoken (a conversation).
    val group = shown.filter { !it.mine && !it.isEvent }.map { it.author }.toSet().size > 1
    // Bubbles of one author in a row (events and gaps end it) share a header.
    fun sameGroup(a: ThreadMessage, b: ThreadMessage) =
        !a.isEvent && !b.isEvent && a.mine == b.mine && a.author == b.author && kotlin.math.abs(b.createdAt - a.createdAt) <= GROUP_GAP_MS
    ChatList(
        items = shown,
        key = { it.id },
        createdAt = { it.createdAt },
        hasOlder = state.window.hasOlder,
        detached = state.window.detached,
        unseen = state.window.unseen,
        actions = actions.list,
        modifier = Modifier.fillMaxSize(),
    ) { index, m ->
        if (m.isEvent) {
            EventRow(m, actions.onOpenAbout)
        } else {
            val first = index == 0 || !sameGroup(shown[index - 1], m)
            val last = index == shown.size - 1 || !sameGroup(m, shown[index + 1])
            MessageBubble(
                m,
                name = (if (room) first && !m.mine else group && !m.mine && first).let { if (it) nameOf(m) else null },
                time = if (last) messageTime(m.createdAt) else null,
                gapAbove = first,
                avatar = room && first,
                withAvatarSpace = room && !m.mine,
            )
        }
    }
}

private fun nameOf(m: ThreadMessage) = m.authorName.ifEmpty { "Unknown member" }

/** "Joep is viewing Roadmap", or "Joep · Started the meeting." for a marker. */
fun eventText(m: ThreadMessage): String {
    val name = m.authorName
    if (m.about != null) {
        val title = m.aboutTitle.ifEmpty { m.about }
        return if (name.isEmpty()) "Viewing $title" else "$name is viewing $title"
    }
    val text = m.text.orEmpty()
    return if (name.isEmpty()) text else "$name · $text"
}

@Composable
private fun EventRow(m: ThreadMessage, onOpen: (String, String) -> Unit) {
    val atomic = MaterialTheme.atomic
    val about = m.about
    Row(
        Modifier.fillMaxWidth().then(if (about != null) Modifier.clickable { onOpen(about, m.aboutTitle) } else Modifier)
            .padding(vertical = 4.dp, horizontal = 4.dp).testTag("event-row"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Outlined.NearMe, null, Modifier.size(13.dp), tint = atomic.textSecondary)
        Text(
            eventText(m),
            Modifier.padding(start = 6.dp).weight(1f),
            color = atomic.textSecondary,
            fontSize = 12.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textDecoration = if (about != null) TextDecoration.Underline else TextDecoration.None,
        )
        Text(messageTime(m.createdAt), Modifier.padding(start = 8.dp), color = atomic.textSecondary, fontSize = 11.sp)
    }
}

@Composable
private fun MessageBubble(
    m: ThreadMessage,
    name: String?,
    time: String?,
    gapAbove: Boolean,
    avatar: Boolean,
    withAvatarSpace: Boolean,
) {
    val atomic = MaterialTheme.atomic
    val mine = m.mine
    val content: @Composable () -> Unit = {
        Column(horizontalAlignment = if (mine) Alignment.End else Alignment.Start) {
            if (name != null) Text(name, Modifier.padding(start = 4.dp, bottom = 2.dp).testTag("message-author"), color = atomic.textSecondary, fontSize = 12.sp)
            Bubble(mine) {
                val text = m.text
                if (text != null) {
                    SelectionContainer { Text(text, color = if (mine) atomic.mainSelectedFg else atomic.textPrimary) }
                } else {
                    Text("This message can't be opened", color = atomic.textSecondary, fontStyle = FontStyle.Italic)
                }
            }
            if (time != null) Text(time, Modifier.padding(start = 4.dp, end = 4.dp, top = 2.dp).testTag("message-time"), color = atomic.textSecondary, fontSize = 11.sp)
        }
    }
    BoxWithConstraints(
        Modifier.fillMaxWidth().padding(top = if (gapAbove) 8.dp else 2.dp, bottom = 2.dp),
        contentAlignment = if (mine) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Row(Modifier.widthIn(max = maxWidth * 0.85f), verticalAlignment = Alignment.Bottom) {
            if (withAvatarSpace) {
                // The avatar sits beside the first bubble of a group; the others keep the space so the bubbles line up.
                Box(Modifier.width(28.dp)) { if (avatar) Avatar(m) }
                Box(Modifier.width(6.dp))
            }
            content()
        }
    }
}

@Composable
private fun Avatar(m: ThreadMessage) {
    val initial = m.authorName.trim().firstOrNull()?.uppercase() ?: "?"
    Box(Modifier.size(28.dp).background(MaterialTheme.atomic.bg2, CircleShape).testTag("message-avatar"), Alignment.Center) {
        Text(initial, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
    }
}
