package place.atomic.app.kotlin.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ManageSearch
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.Perf
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.data.SearchItem
import place.atomic.app.kotlin.data.SearchKind
import place.atomic.app.kotlin.data.SearchState

/** What the search asks of its model and its host. */
class SearchActions(
    val onQuery: (String) -> Unit,
    val onClearKind: () -> Unit,
    val onClearScope: () -> Unit,
    val onSearchInDrive: (String) -> Unit,
    val onOpen: (SearchItem) -> Unit,
)

/**
 * Search (Flutter's `SearchScreen`): the field, a chip that names the kind or
 * the drive searched with a way back to everything, and the results. On a phone
 * it is a page: the best result is drawn nearest the field at the bottom, under
 * the thumb. With [palette] it is the tablet's card over the window (like a
 * browser's cmd+K): the field on top, the results under it, rows at one 16 dp
 * inset and the one Enter opens filled. A drive in the results opens the drive; the
 * explicit icon next to it searches inside it. Stateless but for the text typed.
 */
@Composable
fun SearchPanel(state: SearchState, actions: SearchActions, palette: Boolean, modifier: Modifier = Modifier, initialText: String = "") {
    var text by rememberSaveable { mutableStateOf(initialText) }
    val focus = remember { FocusRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    LaunchedEffect(Unit) {
        focus.requestFocus()
        keyboard?.show()
    }
    // Flutter's `search keystroke to results`: the frame after results for the typed text.
    LaunchedEffect(state.hitsFor) {
        if (state.hitsFor.isNotEmpty()) {
            withFrameNanos { }
            Perf.sinceTyped("search keystroke to results")
        }
    }
    val field: @Composable () -> Unit = {
        Row(
            Modifier.fillMaxWidth().padding(
                horizontal = 16.dp,
                vertical = if (palette) 12.dp else 8.dp,
            ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it; actions.onQuery(it) },
                modifier = Modifier.weight(1f).focusRequester(focus).testTag("search"),
                placeholder = { Text(state.kind.hint) },
                singleLine = true,
                shape = RoundedCornerShape(9.dp),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = { state.items.firstOrNull()?.let(actions.onOpen) }),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = MaterialTheme.atomic.bg1,
                    unfocusedContainerColor = MaterialTheme.atomic.bg1,
                    focusedBorderColor = Color.Transparent,
                    unfocusedBorderColor = Color.Transparent,
                ),
            )
            ScopeChip(state, { text = ""; actions.onClearKind() }, { actions.onClearScope() })
        }
    }
    val results: @Composable (Modifier) -> Unit = { m -> Results(state, actions, palette, m) }
    if (palette) {
        Column(modifier.background(MaterialTheme.colorScheme.background)) {
            field()
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            results(Modifier.weight(1f))
        }
    } else {
        Column(modifier.background(MaterialTheme.colorScheme.background).imePadding()) {
            results(Modifier.weight(1f))
            field()
        }
    }
}

@Composable
private fun ScopeChip(state: SearchState, onClearKind: () -> Unit, onClearScope: () -> Unit) {
    when {
        state.kind != SearchKind.Any -> Chip(state.kind.label, "Search everything", onClearKind, "search-kind")
        state.scope != null -> Chip("In: ${state.scopeName()}", "Search all drives", onClearScope, "search-scope")
    }
}

@Composable
private fun Chip(text: String, clear: String, onClear: () -> Unit, tag: String) {
    val atomic = MaterialTheme.atomic
    Surface(Modifier.padding(start = 8.dp).widthIn(max = 140.dp).testTag(tag), shape = RoundedCornerShape(9.dp), color = atomic.mainSelectedBg) {
        Row(Modifier.padding(start = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f, fill = false), maxLines = 1, overflow = TextOverflow.Ellipsis, color = atomic.mainSelectedFg, fontSize = 12.sp)
            IconButton(onClear, Modifier.size(32.dp)) { Icon(Icons.Outlined.Close, contentDescription = clear, Modifier.size(16.dp), tint = atomic.mainSelectedFg) }
        }
    }
}

@Composable
private fun Results(state: SearchState, actions: SearchActions, palette: Boolean, modifier: Modifier) {
    val atomic = MaterialTheme.atomic
    if (state.error != null) {
        Box(modifier.fillMaxSize(), Alignment.Center) { Text(state.error, color = atomic.alert) }
        return
    }
    val items = state.items
    if (state.nothingFound) {
        Box(modifier.fillMaxSize(), if (palette) Alignment.TopCenter else Alignment.BottomCenter) {
            Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                val where = when {
                    state.kind != SearchKind.Any -> " in ${state.kind.label}"
                    state.scope != null -> " in this drive"
                    else -> ""
                }
                Text("Nothing found for “${state.query}”$where", Modifier.testTag("search-nothing-found"), color = atomic.textSecondary, textAlign = TextAlign.Center)
                if (state.scope != null) TextButton(actions.onClearScope) { Text("Search all drives") }
            }
        }
        return
    }
    val heading = state.showsRecent && items.isNotEmpty()
    LazyColumn(
        modifier.fillMaxSize(),
        // Best first, drawn from the bottom up: nearest the thumb. The palette lists from its field down.
        reverseLayout = !palette,
        contentPadding = if (palette) PaddingValues(vertical = 8.dp) else PaddingValues(0.dp),
    ) {
        // In the reversed list the heading comes last (at the top).
        if (palette && heading) item(key = "heading") { Heading(state.kind.heading, palette) }
        items(items.size, key = { "${items[it].subject}-$it" }) { n -> ResultRow(state, items[n], n == 0, palette, actions) }
        if (!palette && heading) item(key = "heading") { Heading(state.kind.heading, palette) }
    }
}

@Composable
private fun Heading(text: String, palette: Boolean) {
    Text(
        text,
        Modifier.padding(start = if (palette) 32.dp else 16.dp, top = if (palette) 4.dp else 12.dp, end = 16.dp, bottom = 4.dp),
        color = MaterialTheme.atomic.textSecondary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
    )
}

@Composable
private fun ResultRow(state: SearchState, item: SearchItem, top: Boolean, palette: Boolean, actions: SearchActions) {
    val atomic = MaterialTheme.atomic
    val row = RowItem(
        subject = item.subject,
        title = item.title.ifEmpty { item.subject },
        detail = state.detail(item),
        className = item.className,
        emoji = item.emoji,
        drive = item.drive,
    )
    val content: @Composable () -> Unit = {
        ResourceRow(row, { actions.onOpen(item) }, end = if (state.isDrive(item)) ({
            IconButton({ actions.onSearchInDrive(item.subject) }, Modifier.size(48.dp).testTag("search-in-drive-${item.subject}")) {
                Icon(Icons.Outlined.ManageSearch, contentDescription = "Search in ${item.title.ifEmpty { "this drive" }}")
            }
        }) else null)
    }
    if (palette) {
        // Every row at the same inset; the one Enter opens is filled, not outlined (an outline moved its content).
        Surface(
            Modifier.padding(horizontal = 16.dp, vertical = 2.dp).then(if (top) Modifier.testTag("search-top-hit") else Modifier),
            shape = RoundedCornerShape(9.dp), color = if (top) atomic.mainSelectedBg else Color.Transparent,
        ) { content() }
    } else if (top) {
        Surface(
            Modifier.padding(horizontal = 16.dp, vertical = 2.dp).testTag("search-top-hit"),
            shape = RoundedCornerShape(9.dp), color = Color.Transparent, border = BorderStroke(1.5.dp, atomic.main),
        ) { content() }
    } else {
        content()
    }
}
