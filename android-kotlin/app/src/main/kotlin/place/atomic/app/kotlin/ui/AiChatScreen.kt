package place.atomic.app.kotlin.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AddCircleOutline
import androidx.compose.material.icons.outlined.AutoAwesome
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.chat.AiChatState
import place.atomic.app.kotlin.chat.AiStatus
import place.atomic.app.kotlin.chat.ChatEntry
import place.atomic.app.kotlin.chat.ChatPart
import place.atomic.app.kotlin.chat.ContextItem
import place.atomic.app.kotlin.chat.ToolState
import place.atomic.app.kotlin.chat.toolLabel
import place.atomic.app.kotlin.chat.toolSummary
import place.atomic.app.kotlin.chat.toolTitles

/** What the AI chat screen asks of its model and its host. */
class AiChatActions(
    val onBack: () -> Unit,
    val onSend: (String) -> Unit,
    val onStop: () -> Unit,
    val onEnableAi: () -> Unit,
    /** A pill of the new-chat picker, or a chip's remove button. */
    val onToggle: (ContextItem) -> Unit,
    /** A resource picked with the attach button. */
    val onAttach: (ContextItem) -> Unit,
    /** A link of a message: a resource opens in the app, anything else outside it. */
    val onOpenLink: (String) -> Unit,
    val search: suspend (String) -> List<ContextItem>,
    val list: ChatListActions,
    /** The messages are on screen (for the `chat painted` mark). */
    val onPainted: () -> Unit = {},
)

private const val NO_AI_TITLE = "AI chat needs an atomic.place account"
private const val NO_AI_TEXT =
    "The AI runs on the account, and this device has none linked. Your drives, documents and chat rooms work without one."

/**
 * An AI chat (Flutter's `ChatScreen`): the messages as Markdown bubbles with the
 * tool calls as steps, newest at the bottom, and a field to write to the AI.
 * A new chat offers a few resources to give the AI as context. Stateless apart
 * from the text being typed: the state comes in, every action goes out.
 */
@Composable
fun AiChatScreen(state: AiChatState, actions: AiChatActions) {
    var input by rememberSaveable { mutableStateOf("") }
    var picking by remember { mutableStateOf(false) }
    val title = state.title.ifEmpty { if (state.chat == null) "New chat" else "Untitled chat" }
    LaunchedEffect(state.window.loaded) {
        if (state.window.loaded) {
            androidx.compose.runtime.withFrameNanos { }
            actions.onPainted()
        }
    }
    AtomicScaffold(title = title, onBack = actions.onBack) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            Box(Modifier.weight(1f).fillMaxWidth()) { Body(state, actions) }
            AiComposer(state, input, { input = it }, { actions.onSend(input); input = "" }, actions) { picking = true }
        }
    }
    if (picking) {
        ContextPicker(state.options, actions.search, onPick = { actions.onAttach(it); picking = false }, onDismiss = { picking = false })
    }
}

private val AiChatState.noAi get() = ai == AiStatus.NoAccount

@Composable
private fun Body(state: AiChatState, actions: AiChatActions) {
    val atomic = MaterialTheme.atomic
    val error = state.window.error
    if (error != null) {
        Box(Modifier.fillMaxSize().padding(24.dp), Alignment.Center) { Text(error, color = atomic.alert, textAlign = TextAlign.Center) }
        return
    }
    if (!state.loaded) {
        Box(Modifier.fillMaxSize(), Alignment.Center) { Spinner(size = 32.dp) }
        return
    }
    val partial = state.partial?.let { ChatEntry("partial", "assistant", 0, it) }
    val shown = state.messages + listOfNotNull(partial)
    if (shown.isEmpty()) {
        if (state.noAi) NoAiState(state.error) else Picker(state, actions.onToggle)
        return
    }
    ChatList(
        items = shown,
        key = { it.id },
        createdAt = { it.createdAt },
        hasOlder = state.window.hasOlder,
        detached = state.window.detached,
        unseen = state.window.unseen,
        actions = actions.list,
        modifier = Modifier.fillMaxSize(),
        followAnswer = state.sending,
    ) { _, entry -> MessageRow(entry, entry.id == "partial", actions.onOpenLink) }
}

@Composable
private fun MessageRow(entry: ChatEntry, partial: Boolean, onLink: (String) -> Unit) {
    val mine = entry.role == "user"
    BoxWithConstraints(Modifier.fillMaxWidth().padding(vertical = 4.dp), contentAlignment = if (mine) Alignment.CenterEnd else Alignment.CenterStart) {
        // An answer may hold code and tables: a little wider.
        Bubble(mine, Modifier.widthIn(max = maxWidth * if (mine) 0.85f else 0.95f)) { MessageBody(entry, mine, partial, onLink) }
    }
}

/** What a message shows: its text in Markdown, its tool calls as steps, the resources attached as chips. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun MessageBody(entry: ChatEntry, mine: Boolean, partial: Boolean, onLink: (String) -> Unit) {
    val atomic = MaterialTheme.atomic
    if (partial && entry.parts.isEmpty()) {
        Spinner(size = 16.dp)
        return
    }
    val titles = toolTitles(entry.parts)
    val color = if (mine) atomic.mainSelectedFg else atomic.textPrimary
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), horizontalAlignment = if (mine) Alignment.End else Alignment.Start) {
        val chips: List<Pair<String, ContextItem?>> =
            entry.parts.filterIsInstance<ChatPart.File>().map { (it.filename ?: "Attached file") to null } +
                entry.context.map { (it.title.ifEmpty { "Resource" }) to it }
        if (chips.isNotEmpty()) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                for ((label, item) in chips) {
                    AssistChip(
                        onClick = { item?.let { onLink(it.subject) } },
                        label = { Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        leadingIcon = {
                            if (item?.emoji != null) Text(item.emoji) else Icon(iconForClass(item?.className.orEmpty()), null, Modifier.size(16.dp))
                        },
                    )
                }
            }
        }
        for (part in entry.parts) {
            when (part) {
                is ChatPart.Text -> if (part.text.isNotBlank()) MarkdownText(part.text, color = color, inline = mine, onLink = onLink)
                is ChatPart.Tool -> ToolStepRow(part, titles)
                else -> Unit
            }
        }
        // Still thinking after a tool call: the dots say so.
        val last = entry.parts.lastOrNull()
        if (partial && last is ChatPart.Tool && !last.state.running) Spinner(Modifier.padding(top = 6.dp), size = 14.dp)
    }
}

/** One tool call of an answer, as a compact row: what it does, with a spinner while it runs and a check or a cross after. A tap opens what it was given and a short summary of its result. */
@Composable
private fun ToolStepRow(part: ChatPart.Tool, titles: Map<String, String>) {
    val atomic = MaterialTheme.atomic
    var open by remember(part.toolCallId) { mutableStateOf(false) }
    val running = part.state.running
    val failed = part.state == ToolState.OutputError
    val label = toolLabel(part, titles)
    Column(
        Modifier.fillMaxWidth().clickable { open = !open }.padding(vertical = 4.dp).testTag("tool-step-${part.toolCallId}"),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(if (part.toolName.contains("search")) Icons.Outlined.Search else Icons.Outlined.Build, null, Modifier.size(15.dp), tint = atomic.textSecondary)
            Text(
                if (running) "$label…" else label,
                Modifier.weight(1f, fill = false),
                color = atomic.textSecondary,
                fontSize = 13.sp,
                maxLines = if (open) 4 else 1,
                overflow = TextOverflow.Ellipsis,
            )
            when {
                running -> Spinner(size = 14.dp)
                else -> Icon(
                    if (failed) Icons.Outlined.Close else Icons.Outlined.Check,
                    contentDescription = if (failed) "failed" else "done",
                    modifier = Modifier.size(16.dp),
                    tint = if (failed) atomic.alert else atomic.success,
                )
            }
            Icon(if (open) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore, null, Modifier.size(16.dp), tint = atomic.textSecondary)
        }
        if (open) {
            Column(
                Modifier.fillMaxWidth().padding(start = 23.dp, top = 4.dp, bottom = 2.dp)
                    .border(1.dp, atomic.border, RoundedCornerShape(6.dp)).padding(8.dp),
            ) {
                Text("Tool: ${part.toolName}", color = atomic.textSecondary, fontSize = 12.sp)
                val args = (part.input as? org.json.JSONObject)?.toString(2) ?: part.input?.toString() ?: "{}"
                Text(args.take(800), Modifier.padding(top = 4.dp), color = atomic.textSecondary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                if (!running) {
                    Text(toolSummary(part), Modifier.padding(top = 6.dp), color = if (failed) atomic.alert else atomic.textSecondary, fontSize = 12.sp)
                }
            }
        }
    }
}

/** A small pill; the selected one is told apart by colour, not an icon. */
@Composable
private fun Pill(item: ContextItem, on: Boolean, onClick: () -> Unit) {
    val atomic = MaterialTheme.atomic
    val title = if (item.title.length > 22) item.title.take(21) + "…" else item.title
    Surface(
        onClick = onClick,
        shape = CircleShape,
        color = if (on) atomic.main.copy(alpha = 0.12f) else atomic.bg1,
        border = BorderStroke(1.dp, if (on) atomic.main.copy(alpha = 0.6f) else atomic.bg1),
    ) {
        Text(
            if (item.emoji == null) title else "${item.emoji} $title",
            Modifier.padding(horizontal = 11.dp, vertical = 5.dp),
            color = if (on) atomic.main else atomic.textSecondary,
            fontSize = 12.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** What a new chat shows instead of messages: a few resources to give the AI as context. Optional; the chat starts without if nothing is picked. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Picker(state: AiChatState, onToggle: (ContextItem) -> Unit) {
    if (state.options.isEmpty()) return
    Box(Modifier.fillMaxSize().padding(horizontal = 24.dp), Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Add context?", color = MaterialTheme.atomic.textSecondary, fontSize = 12.sp)
            FlowRow(
                Modifier.padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                for (o in state.options) Pill(o, state.attached.any { it.subject == o.subject }) { onToggle(o) }
            }
        }
    }
}

/** What a new chat shows without an AI: why, instead of a context picker for a chat that cannot be had. */
@Composable
private fun NoAiState(error: String?) {
    val atomic = MaterialTheme.atomic
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.AutoAwesome, null, Modifier.size(40.dp), tint = atomic.main)
        Text(NO_AI_TITLE, Modifier.padding(top = 16.dp).testTag("no-ai-title"), fontSize = 18.sp, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        Text(error ?: NO_AI_TEXT, Modifier.padding(top = 8.dp), color = atomic.textSecondary, textAlign = TextAlign.Center)
    }
}

@Composable
private fun Hint(text: String) {
    Text(
        text,
        Modifier.fillMaxWidth().padding(start = 16.dp, top = 8.dp, end = 16.dp, bottom = 16.dp),
        color = MaterialTheme.atomic.textSecondary,
        fontSize = 13.sp,
        textAlign = TextAlign.Center,
    )
}

/** The way to write, when there is an AI to write to; otherwise one line saying so. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AiComposer(
    state: AiChatState,
    input: String,
    onInput: (String) -> Unit,
    onSend: () -> Unit,
    actions: AiChatActions,
    onAttach: () -> Unit,
) {
    val atomic = MaterialTheme.atomic
    when (state.ai) {
        // An empty chat says it in the middle (see NoAiState).
        AiStatus.NoAccount -> if (state.messages.isNotEmpty()) Hint(state.error ?: "$NO_AI_TITLE.")
        AiStatus.NotAvailable -> Hint("Included AI is not available.")
        AiStatus.NeedsConsent -> Column(Modifier.fillMaxWidth().padding(start = 16.dp, top = 8.dp, end = 16.dp, bottom = 16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                "Messages you send here are processed by your account provider's AI, and use your account's credits.",
                color = atomic.textSecondary, fontSize = 13.sp, textAlign = TextAlign.Center,
            )
            Button(actions.onEnableAi, Modifier.padding(top = 8.dp)) { Text("Turn on AI") }
            if (state.error != null) Text(state.error, color = atomic.alert, fontSize = 12.sp)
        }
        // While the AI is looked up, the field is there already, switched off: the messages above stay where they are when the answer lands.
        AiStatus.Looking, AiStatus.Ready -> Composer(
            value = input,
            onValueChange = onInput,
            onSend = onSend,
            enabled = state.ai == AiStatus.Ready,
            sending = state.sending,
            onStop = actions.onStop,
            error = state.error,
            leading = {
                IconButton(onAttach, enabled = state.ai == AiStatus.Ready, modifier = Modifier.testTag("chat-attach")) {
                    Icon(Icons.Outlined.AddCircleOutline, contentDescription = "Attach")
                }
            },
            chips = {
                if (state.attached.isNotEmpty() && (state.messages.isNotEmpty() || state.attached.any { it.subject in state.fromDrive })) {
                    FlowRow(Modifier.padding(bottom = 6.dp), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        for (a in state.attached) {
                            InputChip(
                                selected = false,
                                onClick = { actions.onOpenLink(a.subject) },
                                label = { Text(a.title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                leadingIcon = { if (a.emoji == null) Icon(iconForClass(a.className), null, Modifier.size(16.dp)) else Text(a.emoji) },
                                trailingIcon = {
                                    Icon(Icons.Outlined.Close, "Remove ${a.title}", Modifier.size(16.dp).clickable { actions.onToggle(a) })
                                },
                            )
                        }
                    }
                }
            },
        )
    }
}

/** The attach button: a resource of the person's drives to give the AI as context. Recents first, search when typing. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContextPicker(
    recent: List<ContextItem>,
    search: suspend (String) -> List<ContextItem>,
    onPick: (ContextItem) -> Unit,
    onDismiss: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<ContextItem>?>(null) }
    LaunchedEffect(query) { results = if (query.isBlank()) null else runCatching { search(query) }.getOrDefault(emptyList()) }
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(bottom = 16.dp)) {
            Text("From my drive", Modifier.padding(horizontal = 16.dp), fontWeight = FontWeight.SemiBold)
            OutlinedTextField(
                query, { query = it },
                Modifier.fillMaxWidth().padding(16.dp).testTag("context-search"),
                placeholder = { Text("Search all drives") },
                leadingIcon = { Icon(Icons.Outlined.Search, null) },
                singleLine = true,
                shape = CircleShape,
            )
            val list = results ?: recent
            LazyColumn(Modifier.heightIn(max = 360.dp), contentPadding = PaddingValues(bottom = 8.dp)) {
                items(list, key = { it.subject }) { item ->
                    ResourceRow(
                        place.atomic.app.kotlin.data.RowItem(item.subject, item.title, className = item.className, emoji = item.emoji),
                        onClick = { onPick(item) },
                    )
                }
            }
        }
    }
}
