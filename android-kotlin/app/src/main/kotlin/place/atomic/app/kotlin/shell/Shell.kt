package place.atomic.app.kotlin.shell

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.AppViewModel
import place.atomic.app.kotlin.AtomicApp
import place.atomic.app.kotlin.Perf
import place.atomic.app.kotlin.chat.NativeKind
import place.atomic.app.kotlin.chat.ThreadKind
import place.atomic.app.kotlin.core.createDocument
import place.atomic.app.kotlin.core.noteResourceOpened
import place.atomic.app.kotlin.data.CoreBackend
import place.atomic.app.kotlin.data.CoreHomeRepository
import place.atomic.app.kotlin.data.HomeViewModel
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.data.SearchItem
import place.atomic.app.kotlin.data.SearchModel
import place.atomic.app.kotlin.data.Section
import place.atomic.app.kotlin.ui.ActionPage
import place.atomic.app.kotlin.ui.ActivityPane
import place.atomic.app.kotlin.ui.AtomicDialog
import place.atomic.app.kotlin.ui.BarActions
import place.atomic.app.kotlin.ui.BarPage
import place.atomic.app.kotlin.ui.BottomBar
import place.atomic.app.kotlin.ui.EmbedSlot
import place.atomic.app.kotlin.ui.HomeActions
import place.atomic.app.kotlin.ui.HomeScreen
import place.atomic.app.kotlin.ui.ListPage
import place.atomic.app.kotlin.ui.NewChoice
import place.atomic.app.kotlin.ui.OpenResource
import place.atomic.app.kotlin.ui.ResourceChrome
import place.atomic.app.kotlin.ui.SearchActions
import place.atomic.app.kotlin.ui.SearchPanel
import place.atomic.app.kotlin.ui.SectionRequest
import place.atomic.app.kotlin.ui.SectionsDialog
import place.atomic.app.kotlin.ui.SplitPanes
import place.atomic.app.kotlin.ui.isWide

private const val LIST_WIDTH_KEY = "list_width"
private const val CHAT_ROOM_CLASS = "https://atomicdata.dev/classes/ChatRoom"

/** A search that is open: in one drive ([scope]) or in all; [nonce] starts it over when the button is pressed again. */
data class SearchRequest(val scope: String?, val nonce: Int)

private val SearchRequestSaver = listSaver<SearchRequest?, String>(
    save = { r -> if (r == null) emptyList() else listOf(r.scope.orEmpty(), r.nonce.toString()) },
    restore = { s -> if (s.size == 2) SearchRequest(s[0].ifEmpty { null }, s[1].toIntOrNull() ?: 0) else null },
)

/** The web app's page for a new resource in [drive] (all kinds, or the class given). */
fun newResourcePath(drive: String, classSubject: String? = null): String {
    fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8")
    val query = listOfNotNull(classSubject?.let { "classSubject=${enc(it)}" }, drive.takeIf { it.isNotEmpty() }?.let { "parentSubject=${enc(it)}" })
    return "/app/new" + if (query.isEmpty()) "" else query.joinToString("&", "?")
}

/**
 * What leaving a page does (Flutter visits on leave, not on tap): a resource is
 * noted as opened, which moves it up in the Recents, a drive becomes the
 * active one, a native screen lets the page read its resource again, and the
 * profile editor's changes reach the bottom bar.
 */
fun leaveDestination(app: AppViewModel, atomic: AtomicApp, d: Destination) {
    if (d.isResource) {
        runCatching { noteResourceOpened(d.drive, d.subject) }
        if (d.isDrive) app.activateDrive(d.subject)
        // The native screen can have changed it (a renamed chat room, a new message): the page reads it again.
        if (d.kind != null) atomic.embed.bridge.changed(listOf(d.subject))
    }
    if (d.kind == Destination.Kinds.PROFILE || d.kind == Destination.Kinds.SETTINGS) app.identity.refresh()
}

/**
 * The signed-in app (Flutter's `AppShell`): the Home and the pages opened from
 * it. From [place.atomic.app.kotlin.ui.SPLIT_FROM_DP] wide the Home is a sidebar
 * with the bottom bar at its foot, next to the pages, which start with the
 * Activity feed; narrower, the pages replace the Home and the bar stays under
 * them (it makes room for the keyboard).
 */
@OptIn(ExperimentalLayoutApi::class, ExperimentalFoundationApi::class)
@Composable
fun Shell(app: AppViewModel, atomic: AtomicApp, onPair: () -> Unit) {
    val context = LocalContext.current
    val split = isWide(LocalConfiguration.current.screenWidthDp)
    val dark = isSystemInDarkTheme()
    val scope = rememberCoroutineScope()
    val vm: HomeViewModel = viewModel(factory = viewModelFactory { initializer { HomeViewModel(CoreHomeRepository(), app.uiPrefs) } })
    val home by vm.state.collectAsStateWithLifecycle()
    val identity by app.identity.state.collectAsStateWithLifecycle()

    val pages = rememberSaveable(saver = StackSaver) { mutableStateListOf<Destination>() }
    val stack = remember(app, atomic) { PageStack(pages) { leaveDestination(app, atomic, it) } }
    var newChats by rememberSaveable { mutableIntStateOf(0) }
    var searchRequest by rememberSaveable(stateSaver = SearchRequestSaver) { mutableStateOf<SearchRequest?>(null) }
    var searches by rememberSaveable { mutableIntStateOf(0) }
    var folded by rememberSaveable { mutableStateOf(false) }
    var listWidth by remember { mutableStateOf(app.uiPrefs.getString(LIST_WIDTH_KEY)?.toFloatOrNull()) }
    var sectionsDialog by rememberSaveable { mutableStateOf(false) }
    var pickDrive by rememberSaveable { mutableStateOf(false) }
    var newDocument by rememberSaveable { mutableStateOf(false) }
    var request by remember { mutableStateOf<SectionRequest?>(null) }
    var requests by rememberSaveable { mutableIntStateOf(0) }
    val homeList = rememberLazyListState()

    LaunchedEffect(Unit) {
        atomic.startEmbed()
        app.identity.refresh()
    }
    LaunchedEffect(dark) { atomic.embed.bridge.setColorScheme(dark) }
    // Flutter's `home painted`: the frame after every list is in; then the search index is warmed.
    val loaded = home.sections.size == Section.entries.size
    LaunchedEffect(loaded) {
        if (loaded) {
            withFrameNanos { }
            Perf.once("home painted")
            vm.warmSearch()
        }
    }

    fun open(d: Destination, replace: Boolean) {
        searchRequest = null
        if (replace) stack.reset(d) else stack.push(d)
    }

    // The page asks for a native screen (a meeting's chat room): open it when the app has one.
    DisposableEffect(Unit) {
        atomic.nativeOpener = { kind, subject, title ->
            val native = NativeKind.of(kind)
            if (native != null) {
                val drive = pages.lastOrNull { it.kind == null }?.drive.orEmpty()
                stack.push(Destination(native.name, subject, title, drive))
            }
            native != null
        }
        onDispose { atomic.nativeOpener = null }
    }
    val openLink: (String) -> Unit = { link ->
        if (link.startsWith("did:")) {
            stack.push(Destination(null, link, "", pages.lastOrNull()?.drive.orEmpty()))
        } else {
            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link))) }
        }
    }
    // Next to the pages a tap in the sidebar replaces what the pages show; on a phone it adds a page.
    val openRow: (RowItem) -> Unit = { row ->
        open(Destination(NativeKind.of(row.className)?.name, row.subject, row.title, row.drive.ifEmpty { row.subject }), replace = split)
    }
    val homeActions = HomeActions(
        onOpen = openRow,
        onShowAll = { section ->
            request = null
            vm.showAll(section)
            open(Destination(Destination.Kinds.LIST, section.name, section.title, ""), replace = split)
        },
        onToggle = vm::toggleCollapsed,
        onCustomize = { sectionsDialog = true },
        onShowMine = vm::setShowMine,
    )

    val top = pages.lastOrNull()
    val goHome = { searchRequest = null; stack.reset() }
    val activeDrive = { runCatching { CoreBackend.activeDrive() }.getOrNull().orEmpty() }
    val barActions = BarActions(
        onHome = if (searchRequest == null && stack.isEmpty) null else goHome,
        onSection = { section ->
            goHome()
            request = SectionRequest(section, ++requests)
        },
        onSearch = { drive -> searchRequest = SearchRequest(drive, ++searches) },
        onMoreDrives = { pickDrive = true },
        onNew = { choice ->
            val drive = activeDrive()
            when (choice) {
                NewChoice.AiChat -> open(Destination(NativeKind.AiChat.name, "", "", "", newChats++), replace = true)
                NewChoice.Document -> newDocument = true
                NewChoice.ChatRoom -> open(Destination(Destination.Kinds.ACTION, newResourcePath(drive, CHAT_ROOM_CLASS), "New chat room", drive), replace = true)
                NewChoice.Drive -> open(Destination(Destination.Kinds.ACTION, "/app/new-drive", "New drive", drive), replace = true)
                NewChoice.Other -> open(Destination(Destination.Kinds.ACTION, newResourcePath(drive), "New", drive), replace = true)
            }
        },
        onProfile = { if (top?.kind != Destination.Kinds.PROFILE) open(Destination(Destination.Kinds.PROFILE, "", "Profile", ""), replace = true) },
        onSettings = { if (top?.kind != Destination.Kinds.SETTINGS) open(Destination(Destination.Kinds.SETTINGS, "", "Settings", ""), replace = true) },
        onCloseSidebar = { folded = true },
    )
    val current = when {
        searchRequest != null -> BarPage.Search
        top == null -> BarPage.Home
        else -> when (top.barPage) {
            BarKind.Settings -> BarPage.Settings
            BarKind.Profile -> BarPage.Profile
            BarKind.New -> BarPage.New
            BarKind.Other -> BarPage.Other
        }
    }
    val bar: @Composable () -> Unit = {
        BottomBar(split, current, home.layout.visible, home.drives, identity, barActions)
    }
    val homeContent: @Composable () -> Unit = {
        HomeScreen(home, homeActions, split = split, request = request, listState = homeList)
    }

    val pageArea: @Composable () -> Unit = {
        Box(Modifier.fillMaxSize()) {
            // The warm web view stays under the pages; only a resource on top shows it.
            EmbedSlot(atomic.embed, visible = top != null && top.kind == null)
            when {
                top == null -> if (split) ActivityPane(home.sections[Section.Activity], home.showMine, vm::setShowMine, openRow) else homeContent()
                else -> key(top.kind, top.subject, top.nonce) {
                    when (top.kind) {
                        null -> ResourceChrome(OpenResource(top.subject, top.title, top.drive), atomic.embed, onClose = stack::pop)
                        Destination.Kinds.LIST -> Section.byName(top.subject)?.let {
                            BackHandler(onBack = stack::pop)
                            ListPage(it, home, openRow, onBack = stack::pop, onLoadMore = vm::loadMoreChats)
                        }
                        Destination.Kinds.SETTINGS, Destination.Kinds.PROFILE -> SettingsHost(
                            app,
                            profile = top.kind == Destination.Kinds.PROFILE,
                            onEditProfile = { stack.push(Destination(Destination.Kinds.PROFILE, "", "Profile", "")) },
                            onBack = stack::pop,
                            onPair = onPair,
                        )
                        Destination.Kinds.ACTION -> {
                            val controller = remember { atomic.actionEmbed(top.subject, dark) }
                            DisposableEffect(controller) { onDispose { atomic.release(controller) } }
                            ActionPage(top.title, controller, onClose = stack::pop)
                        }
                        else -> when (NativeKind.valueOf(top.kind)) {
                            NativeKind.AiChat -> AiChatHost(atomic, top, onBack = stack::pop, onOpenLink = openLink)
                            NativeKind.Conversation -> ThreadHost(top, ThreadKind.Conversation, onBack = stack::pop, onOpen = openLink)
                            NativeKind.Room -> ThreadHost(top, ThreadKind.Room, onBack = stack::pop, onOpen = openLink)
                        }
                    }
                }
            }
            // A phone: the search is a page over the pages; the bar stays under it.
            if (!split) searchRequest?.let { SearchHost(it, split = false, onClose = { searchRequest = null }, onOpen = { item, isDrive -> open(hitDestination(item, isDrive), replace = false) }) }
        }
    }

    if (split) {
        SplitPanes(
            folded = folded,
            onFolded = { folded = it },
            listWidth = listWidth,
            onListWidth = {
                listWidth = it
                app.uiPrefs.putString(LIST_WIDTH_KEY, it.toString())
            },
            list = { Box(Modifier.fillMaxSize().consumeWindowInsets(WindowInsets.navigationBars)) { homeContent() } },
            bar = bar,
            detail = { Box(Modifier.fillMaxSize().imePadding()) { pageArea() } },
        )
        // The tablet's search is a card over the window, like a browser's cmd+K.
        searchRequest?.let {
            Dialog(onDismissRequest = { searchRequest = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Box(
                    Modifier.fillMaxSize().clickable(indication = null, interactionSource = remember { androidx.compose.foundation.interaction.MutableInteractionSource() }) { searchRequest = null }.padding(top = 72.dp, start = 16.dp, end = 16.dp),
                    contentAlignment = Alignment.TopCenter,
                ) {
                    Surface(
                        Modifier.widthIn(max = 640.dp).fillMaxWidth().heightIn(max = (LocalConfiguration.current.screenHeightDp * 0.7f).dp)
                            .clickable(indication = null, interactionSource = remember { androidx.compose.foundation.interaction.MutableInteractionSource() }) {},
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.background,
                        shadowElevation = 12.dp,
                    ) {
                        SearchHost(it, split = true, onClose = { searchRequest = null }, onOpen = { item, isDrive -> open(hitDestination(item, isDrive), replace = true) })
                    }
                }
            }
        }
    } else {
        Column(Modifier.fillMaxSize().imePadding()) {
            Box(Modifier.weight(1f).fillMaxWidth().consumeWindowInsets(WindowInsets.navigationBars)) { pageArea() }
            if (!WindowInsets.isImeVisible) bar()
        }
    }
    BackHandler(enabled = searchRequest != null && !split) { searchRequest = null }

    if (sectionsDialog) SectionsDialog(home.layout, vm::setLayout, onDone = { sectionsDialog = false }, wide = split)
    if (pickDrive) {
        DrivePicker(home.drives.map { it.subject to it.name.ifEmpty { "Untitled drive" } }, onDismiss = { pickDrive = false }) {
            pickDrive = false
            searchRequest = SearchRequest(it, ++searches)
        }
    }
    if (newDocument) {
        NewDocumentDialog(onDismiss = { newDocument = false }) { name ->
            newDocument = false
            scope.launch {
                val drive = activeDrive()
                runCatching { createDocument(drive, name) }.onSuccess { subject ->
                    open(Destination(null, subject, name, drive), replace = split)
                }
            }
        }
    }
}

private fun hitDestination(item: SearchItem, isDrive: Boolean) =
    Destination(NativeKind.of(item.className)?.name, item.subject, item.title, if (isDrive) item.subject else item.drive.ifEmpty { item.subject })

@Composable
private fun SearchHost(request: SearchRequest, split: Boolean, onClose: () -> Unit, onOpen: (SearchItem, Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    val model = remember(request) { SearchModel(CoreHomeRepository(), scope, request.scope) }
    val state by model.state.collectAsStateWithLifecycle()
    SearchPanel(
        state,
        SearchActions(
            onQuery = model::setQuery,
            onClearKind = model::clearKind,
            onClearScope = model::clearScope,
            onSearchInDrive = model::searchInDrive,
            onOpen = { item -> onOpen(item, model.state.value.isDrive(item)) },
        ),
        palette = split,
        modifier = if (split) Modifier else Modifier.fillMaxSize(),
    )
}

/** The Search button's "More…": every drive, to search in one. */
@Composable
private fun DrivePicker(drives: List<Pair<String, String>>, onDismiss: () -> Unit, onPick: (String) -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Search in a drive") },
        text = {
            Column {
                drives.forEach { (subject, name) ->
                    Text(name, Modifier.fillMaxWidth().clickable { onPick(subject) }.padding(vertical = 12.dp).testTag("drive-pick"))
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun NewDocumentDialog(onDismiss: () -> Unit, onCreate: (String) -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    AtomicDialog("New document", onDismiss, "Create", { onCreate(name.trim()) }, confirmEnabled = name.isNotBlank()) {
        OutlinedTextField(name, { name = it }, singleLine = true, placeholder = { Text("Name") }, modifier = Modifier.testTag("new-document-name"))
    }
}
