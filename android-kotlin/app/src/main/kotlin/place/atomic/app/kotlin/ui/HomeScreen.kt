package place.atomic.app.kotlin.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.animateScrollBy
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.Perf
import place.atomic.app.kotlin.data.AllChats
import place.atomic.app.kotlin.data.HOME_ROWS
import place.atomic.app.kotlin.data.HomeState
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.data.Section
import java.time.Instant
import java.time.ZoneId

/** What the Home list asks of its host. */
class HomeActions(
    val onOpen: (RowItem) -> Unit,
    val onShowAll: (Section) -> Unit,
    val onToggle: (Section) -> Unit,
    /** Holding a heading: the dialog that turns sections on and off and arranges them. */
    val onCustomize: () -> Unit,
    val onShowMine: (Boolean) -> Unit,
)

/** The Home button's menu picked [section] (the n-th time): unfold it, scroll it into view, open its full list. */
data class SectionRequest(val section: Section, val n: Int)

/** One line of the Home list; the list is built from these so a section's place is known. */
private sealed interface Entry {
    val key: String

    data class Heading(val section: Section) : Entry { override val key = "${section.name}|h" }
    data class Item(val section: Section, val row: RowItem) : Entry { override val key = "${section.name}|r|${row.subject}" }
    data class ShowAll(val section: Section, val count: Int) : Entry { override val key = "${section.name}|a" }
    data class Note(val section: Section, val loading: Boolean, val text: String) : Entry { override val key = "${section.name}|n" }
    data object Nothing : Entry { override val key = "nothing" }
}

private fun entries(state: HomeState, split: Boolean): List<Entry> = buildList {
    val sections = state.layout.visible.filter { !(split && it == Section.Activity) }
    for (section in sections) {
        val rows = state.sections[section]
        // Left out, with its heading, until it is known to have something.
        if (section.hideEmpty && rows.isNullOrEmpty()) continue
        add(Entry.Heading(section))
        if (section in state.layout.collapsed) continue
        when {
            rows == null -> add(Entry.Note(section, loading = true, text = ""))
            rows.isEmpty() -> add(Entry.Note(section, loading = false, text = if (section == Section.Activity && state.showMine) "Nothing changed yet" else section.empty))
            else -> {
                rows.take(HOME_ROWS).forEach { add(Entry.Item(section, it)) }
                if (rows.size > HOME_ROWS) add(Entry.ShowAll(section, rows.size))
            }
        }
    }
    if (sections.isEmpty()) add(Entry.Nothing)
}

/**
 * The Home (Flutter's `ChatsScreen`): one scrollable page of small sections, each
 * with its newest four rows and a "Show all (N)" row below them. A heading folds
 * its section on a tap and opens the Home sections dialog on a hold; the Activity
 * heading has the "Show mine" chip. Search and New are the bar's. Next to the pages
 * ([split]) the activity is the detail pane's home page, not a section. Stateless:
 * the state comes in, every action goes out, so the screenshot tests run it with
 * fake data.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    state: HomeState,
    actions: HomeActions,
    modifier: Modifier = Modifier,
    split: Boolean = false,
    request: SectionRequest? = null,
    listState: LazyListState = rememberLazyListState(),
) {
    val list = remember(state.sections, state.layout, state.showMine, split) { entries(state, split) }
    // The Home button's menu (or a tap on a heading that unfolds): unfold, scroll into view, open the list.
    LaunchedEffect(request?.n) {
        val r = request ?: return@LaunchedEffect
        if (r.section in state.layout.collapsed) actions.onToggle(r.section)
        withFrameNanos { }
        withFrameNanos { }
        listState.reveal(list, r.section)
        actions.onShowAll(r.section)
    }
    androidx.compose.material3.Scaffold(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("atomic", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), state = listState) {
            items(list.size, key = { list[it].key }) { i ->
                when (val e = list[i]) {
                    is Entry.Heading -> SectionHeading(
                        e.section.title,
                        collapsed = e.section in state.layout.collapsed,
                        onToggle = {
                            val unfolding = e.section in state.layout.collapsed
                            actions.onToggle(e.section)
                            if (unfolding) {
                                // Reveal the section just unfolded (a request with the same effect, without opening it).
                            }
                        },
                        onHold = actions.onCustomize,
                        tag = e.section.name,
                        trailing = if (e.section == Section.Activity) ({ ShowMineChip(state.showMine, actions.onShowMine) }) else null,
                    )
                    is Entry.Item -> ResourceRow(e.row, { actions.onOpen(e.row) })
                    is Entry.ShowAll -> ShowAllRow(e.count, { actions.onShowAll(e.section) }, e.section.name)
                    is Entry.Note -> if (e.loading) Loading() else Empty(e.text)
                    Entry.Nothing -> Column(Modifier.fillMaxWidth().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("All sections are off", color = MaterialTheme.atomic.textSecondary)
                        TextButton(actions.onCustomize) { Text("Customize") }
                    }
                }
            }
        }
    }
    // After a heading unfolds, bring it into view.
    val unfolded = remember { mutableSetOf<Section>() }
    LaunchedEffect(state.layout.collapsed) {
        val now = state.layout.collapsed
        val opened = unfolded.filter { it !in now }
        unfolded.clear()
        unfolded.addAll(now)
        if (opened.size == 1) {
            withFrameNanos { }
            withFrameNanos { }
            listState.reveal(entries(state, split), opened.single())
        }
    }
}

/**
 * Scrolls so the [section], just unfolded, can be seen: as little as needed when
 * its heading and rows fit in the room (none when they already do), the heading
 * at the top when the section is taller than that.
 */
internal suspend fun LazyListState.reveal(list: List<*>, section: Section) {
    val prefix = "${section.name}|"
    val infos = layoutInfo.visibleItemsInfo
    val mine = infos.filter { (it.key as? String)?.startsWith(prefix) == true }
    val heading = infos.firstOrNull { it.key == "$prefix" + "h" }
    val all = list.indices.filter { ((list[it] as? Entry)?.key ?: "").startsWith(prefix) }
    if (all.isEmpty()) return
    if (heading == null) {
        // Out of sight: bring the heading to the top.
        animateScrollToItem(all.first())
        return
    }
    val average = if (mine.isEmpty()) 0 else mine.sumOf { it.size } / mine.size
    val height = mine.sumOf { it.size } + (all.size - mine.size) * average
    val viewport = layoutInfo.viewportEndOffset - layoutInfo.viewportStartOffset
    val delta = revealDelta(heading.offset.toFloat(), height.toFloat(), viewport.toFloat())
    if (delta != 0f) animateScrollBy(delta)
}

/**
 * How far to scroll (positive: down the page) so a section whose heading is at
 * [headingTop] and that is [height] tall shows in a viewport of [viewport]:
 * nothing when it fits already, the minimum to show its end when it fits the
 * viewport, its heading at the top when it is taller.
 */
fun revealDelta(headingTop: Float, height: Float, viewport: Float): Float {
    if (height >= viewport) return headingTop
    if (headingTop < 0f) return headingTop
    val bottom = headingTop + height
    return if (bottom > viewport) bottom - viewport else 0f
}

/**
 * The heading: its title (a tap folds, a hold arranges) with a rounded wash that
 * hugs the title and its chevron, and the section's own control at the right edge.
 * 15 sp, nearly the text colour, 48 dp high.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun SectionHeading(
    title: String,
    collapsed: Boolean,
    onToggle: () -> Unit,
    onHold: () -> Unit,
    tag: String,
    trailing: (@Composable () -> Unit)? = null,
) {
    val atomic = MaterialTheme.atomic
    val haptic = LocalHapticFeedback.current
    val turn by animateFloatAsState(if (collapsed) -90f else 0f, label = "chevron")
    Row(Modifier.fillMaxWidth().padding(top = 8.dp).heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        Row(
            Modifier
                .padding(start = 8.dp)
                .heightIn(min = 48.dp)
                .clip(RoundedCornerShape(8.dp))
                .combinedClickable(onClick = onToggle, onLongClick = { haptic.performHapticFeedback(HapticFeedbackType.LongPress); onHold() })
                .padding(horizontal = 8.dp)
                .testTag("section-heading-$tag"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis, color = atomic.textPrimary.copy(alpha = 0.85f), fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
            Icon(Icons.Outlined.ExpandMore, contentDescription = null, Modifier.padding(start = 4.dp).size(22.dp).rotate(turn), tint = atomic.textSecondary)
        }
        Box(Modifier.weight(1f))
        trailing?.invoke()
    }
}

/** The activity's "Show mine" filter: the person's own changes too, by You. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShowMineChip(value: Boolean, onChange: (Boolean) -> Unit) {
    FilterChip(
        selected = value,
        onClick = { onChange(!value) },
        label = { Text("Show mine") },
        modifier = Modifier.padding(start = 4.dp, end = 8.dp).testTag("show-mine"),
    )
}

/** The last row of a section with more than [HOME_ROWS] rows: "Show all (N)" at the rows' inset, 48 dp high. */
@Composable
private fun ShowAllRow(count: Int, onClick: () -> Unit, tag: String) {
    Box(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).combinedClickable(onClick = onClick).padding(horizontal = 16.dp).testTag("section-show-all-$tag"),
        contentAlignment = Alignment.CenterStart,
    ) { Text("Show all ($count)", color = MaterialTheme.atomic.main, fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
}

@Composable
private fun Loading() {
    Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
    }
}

/** One quiet line under the heading, where the first row would start. */
@Composable
private fun Empty(text: String) {
    Text(text, Modifier.padding(start = 16.dp, top = 4.dp, end = 16.dp, bottom = 16.dp), color = MaterialTheme.atomic.textSecondary)
}

/**
 * A section's full list: a page on a phone, the detail pane on a tablet. The AI
 * chats are pages from the host ([AllChats]), the next one read within ten rows
 * of the end, under headings by age; `[perf] chats all painted N` marks the
 * frame the list first shows.
 */
@Composable
fun ListPage(
    section: Section,
    state: HomeState,
    onOpen: (RowItem) -> Unit,
    onBack: () -> Unit,
    onLoadMore: () -> Unit,
    modifier: Modifier = Modifier,
    now: Long = System.currentTimeMillis(),
) {
    val chats = section == Section.Chats
    val rows = if (chats) state.allChats.rows else state.sections[section].orEmpty()
    val entries: List<Any> = remember(rows, chats) {
        if (chats) groupChatsByAge(rows, now).flatMap { (label, group) -> listOf(label) + group } else rows
    }
    val more = chats && !state.allChats.done
    if (chats) {
        val opened = remember { Perf.clock() }
        LaunchedEffect(Unit) {
            withFrameNanos { }
            Perf.span("chats all painted ${rows.size}", Perf.clock() - opened)
        }
    }
    AtomicScaffold(section.title, onBack) { padding ->
        LazyColumn(modifier.padding(padding).fillMaxSize().testTag("list-page")) {
            items(entries.size + if (more) 1 else 0, key = { i -> entries.getOrNull(i)?.let { e -> if (e is RowItem) "r-${e.subject}" else "h-$e" } ?: "loading" }) { i ->
                if (chats && i >= entries.size + (if (more) 1 else 0) - 10) onLoadMore()
                when (val e = entries.getOrNull(i)) {
                    is RowItem -> ResourceRow(e, { onOpen(e) })
                    is String -> Text(e, Modifier.padding(start = 16.dp, top = 12.dp, end = 16.dp, bottom = 4.dp), color = MaterialTheme.atomic.textSecondary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    else -> Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp) }
                }
            }
        }
    }
}

/**
 * [rows] (newest first) under small headings by how long ago they were last
 * active: Today, Yesterday, This week, This month, Earlier. A heading appears only
 * when it has chats; a chat without any activity goes last.
 */
fun groupChatsByAge(rows: List<RowItem>, now: Long = System.currentTimeMillis(), zone: ZoneId = ZoneId.systemDefault()): List<Pair<String, List<RowItem>>> {
    val today = Instant.ofEpochMilli(now).atZone(zone).toLocalDate()
    fun label(row: RowItem): String {
        if (row.at <= 0) return "Earlier"
        val days = java.time.temporal.ChronoUnit.DAYS.between(Instant.ofEpochMilli(row.at).atZone(zone).toLocalDate(), today)
        return when {
            days <= 0 -> "Today"
            days == 1L -> "Yesterday"
            days < 7 -> "This week"
            days < 31 -> "This month"
            else -> "Earlier"
        }
    }
    val groups = rows.groupBy(::label)
    return listOf("Today", "Yesterday", "This week", "This month", "Earlier").mapNotNull { name -> groups[name]?.let { name to it } }
}

/** The detail pane's home page when nothing is open: the activity feed, big, with the "Show mine" chip. */
@Composable
fun ActivityPane(rows: List<RowItem>?, showMine: Boolean, onShowMine: (Boolean) -> Unit, onOpen: (RowItem) -> Unit, modifier: Modifier = Modifier) {
    val atomic = MaterialTheme.atomic
    Box(modifier.fillMaxSize().background(MaterialTheme.colorScheme.background), contentAlignment = Alignment.TopCenter) {
        LazyColumn(Modifier.widthIn(max = 720.dp).fillMaxWidth().testTag("activity-pane")) {
            item(key = "title") {
                Row(Modifier.fillMaxWidth().padding(start = 16.dp, top = 24.dp, bottom = 8.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("Activity", Modifier.weight(1f), fontSize = 28.sp, fontWeight = FontWeight.Bold)
                    ShowMineChip(showMine, onShowMine)
                }
            }
            when {
                rows == null -> item(key = "loading") { Loading() }
                rows.isEmpty() -> item(key = "empty") { Empty(if (showMine) "Nothing changed yet" else "No activity from others yet") }
                else -> items(rows.size, key = { "${rows[it].subject}-$it" }) { ResourceRow(rows[it], { onOpen(rows[it]) }) }
            }
        }
    }
}
