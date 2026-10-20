package place.atomic.app.kotlin.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.data.HOME_ROWS
import place.atomic.app.kotlin.data.HomeState
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.data.Section

/** Width from which the list sits next to a detail pane (the tablet layout). */
private const val SPLIT_FROM_DP = 840

/**
 * The Home screen: one scrollable page of small sections (Drives, Recents, AI
 * chats, Favorites, Messages), each with its newest four rows and a "Show
 * all" for the rest, a search field on top that replaces them with results
 * while it has text, and an avatar button for settings (not built yet).
 *
 * Stateless: the state comes in, every action goes out, so the screenshot
 * tests run it with fake data.
 */
@Composable
fun HomeScreen(
    state: HomeState,
    onQuery: (String) -> Unit,
    onShowAll: (Section?) -> Unit,
    onOpen: (RowItem) -> Unit,
    onSettings: () -> Unit,
    modifier: Modifier = Modifier,
    wide: Boolean = false,
    /** Starts a chat with the AI; the AI chats heading offers it. */
    onNewChat: (() -> Unit)? = null,
) {
    val list: @Composable (Modifier) -> Unit = { m -> HomeList(state, onQuery, onShowAll, onOpen, onSettings, onNewChat, m) }
    if (wide) {
        Row(modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
            list(Modifier.width(420.dp).fillMaxHeight())
            Box(
                Modifier.weight(1f).fillMaxHeight().background(MaterialTheme.atomic.bg1),
                contentAlignment = Alignment.Center,
            ) { Text("Select something to open it here", color = MaterialTheme.atomic.textSecondary) }
        }
    } else {
        list(modifier.fillMaxSize())
    }
}

/** True from [SPLIT_FROM_DP] wide: the tablet layout. */
fun isWide(widthDp: Int) = widthDp >= SPLIT_FROM_DP

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeList(
    state: HomeState,
    onQuery: (String) -> Unit,
    onShowAll: (Section?) -> Unit,
    onOpen: (RowItem) -> Unit,
    onSettings: () -> Unit,
    onNewChat: (() -> Unit)?,
    modifier: Modifier,
) {
    val all = state.showAll
    BackHandler(enabled = all != null) { onShowAll(null) }
    Scaffold(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(all?.title ?: "atomic", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    if (all != null) {
                        IconButton(onClick = { onShowAll(null) }) {
                            Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                actions = { Avatar(state.agentName, onSettings) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding)) {
            if (all != null) {
                allRows(state, all, onOpen)
            } else {
                item { SearchField(state.query, onQuery) }
                if (state.searching) searchRows(state, onOpen) else sectionRows(state, onShowAll, onOpen, onNewChat)
            }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.sectionRows(
    state: HomeState,
    onShowAll: (Section?) -> Unit,
    onOpen: (RowItem) -> Unit,
    onNewChat: (() -> Unit)?,
) {
    for (section in Section.entries) {
        val rows = state.sections[section]
        // Left out, with its heading, while there is nothing to list.
        if (section.hideEmpty && rows.isNullOrEmpty()) continue
        item(key = "h-${section.name}") {
            SectionHeading(
                section.title,
                if ((rows?.size ?: 0) > HOME_ROWS) ({ onShowAll(section) }) else null,
                if (section == Section.Chats) onNewChat else null,
            )
        }
        when {
            rows == null -> item(key = "l-${section.name}") { Loading() }
            rows.isEmpty() -> item(key = "e-${section.name}") { Empty(section.empty) }
            else -> items(rows.take(HOME_ROWS), key = { "${section.name}-${it.subject}" }) { ResourceRow(it, { onOpen(it) }) }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.allRows(state: HomeState, section: Section, onOpen: (RowItem) -> Unit) {
    items(state.sections[section].orEmpty(), key = { "${section.name}-${it.subject}" }) { ResourceRow(it, { onOpen(it) }) }
}

private fun androidx.compose.foundation.lazy.LazyListScope.searchRows(state: HomeState, onOpen: (RowItem) -> Unit) {
    val results = state.results
    when {
        results == null -> item { Loading() }
        results.isEmpty() -> item { Empty("No results for “${state.query.trim()}”") }
        else -> {
            item(key = "h-results") { SectionHeading("Results", null) }
            items(results, key = { "r-${it.subject}" }) { ResourceRow(it, { onOpen(it) }) }
        }
    }
}

@Composable
private fun SearchField(query: String, onQuery: (String) -> Unit) {
    OutlinedTextField(
        value = query,
        onValueChange = onQuery,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag("search"),
        placeholder = { Text("Search all drives") },
        leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQuery("") }) { Icon(Icons.Outlined.Close, contentDescription = "Clear") }
            }
        },
        singleLine = true,
        shape = CircleShape,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
        keyboardActions = KeyboardActions.Default,
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = MaterialTheme.atomic.bg1,
            unfocusedContainerColor = MaterialTheme.atomic.bg1,
            unfocusedBorderColor = MaterialTheme.atomic.border,
        ),
    )
}

@Composable
private fun SectionHeading(title: String, onShowAll: (() -> Unit)?, onNew: (() -> Unit)? = null) {
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, top = 12.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            title,
            Modifier.weight(1f),
            color = MaterialTheme.atomic.textSecondary,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
        )
        if (onNew != null) {
            Text(
                "New chat",
                Modifier.clickable(onClick = onNew).padding(horizontal = 8.dp, vertical = 4.dp).testTag("new-chat"),
                color = MaterialTheme.colorScheme.primary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
            )
        }
        if (onShowAll != null) {
            Text(
                "Show all",
                Modifier.clickable(onClick = onShowAll).padding(horizontal = 16.dp, vertical = 4.dp),
                color = MaterialTheme.colorScheme.primary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}

@Composable
private fun Loading() {
    Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
    }
}

@Composable
private fun Empty(text: String) {
    Text(text, Modifier.padding(start = 16.dp, top = 4.dp, end = 16.dp, bottom = 16.dp), color = MaterialTheme.atomic.textSecondary)
}

/** The way into settings: the agent's initial in a circle. */
@Composable
private fun Avatar(name: String, onClick: () -> Unit) {
    AgentAvatar(
        name,
        Modifier.padding(end = 12.dp).clickable(onClick = onClick).testTag("avatar"),
    )
}
