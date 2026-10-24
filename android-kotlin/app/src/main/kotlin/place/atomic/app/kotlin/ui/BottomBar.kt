package place.atomic.app.kotlin.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.border
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.AddBox
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Forum
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.MoreHoriz
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.data.Identity
import place.atomic.app.kotlin.data.Section

/** The page a button of the bar stands for; the one on top is drawn in the main colour. */
enum class BarPage { Home, Search, New, Profile, Settings, Other }

/** What the New button's list offers. */
enum class NewChoice { AiChat, Document, ChatRoom, Drive, Other }

/** The icon of a Home section in the Home button's menu. */
fun sectionIcon(s: Section): ImageVector = when (s) {
    Section.Drives -> Icons.Outlined.Folder
    Section.Activity -> Icons.Outlined.Bolt
    Section.Chats -> Icons.Outlined.ChatBubbleOutline
    Section.Favorites -> Icons.Outlined.Star
    Section.Messages -> Icons.Outlined.Forum
}

/** What New offers, the most used first. */
val newItems = listOf(
    HoldItem("AI chat", NewChoice.AiChat, Icons.Outlined.ChatBubbleOutline),
    HoldItem("Document", NewChoice.Document, Icons.Outlined.Description),
    HoldItem("New chat room", NewChoice.ChatRoom, Icons.Outlined.Forum),
    HoldItem("New drive", NewChoice.Drive, Icons.Outlined.Folder),
    HoldItem("Other…", NewChoice.Other, Icons.Outlined.AddBox),
)

/** Most drives the Search button's list names. */
private const val LIST_DRIVES = 4
private const val MORE_DRIVES = "\u0000more"
private const val ALL_DRIVES = ""

/** The height of the row of buttons, above the system inset. */
val BAR_ROW_HEIGHT = 56.dp
private val MAX_BUTTONS_WIDTH = 560.dp

class BarActions(
    /** Null when Home is where the person is (the button then does nothing). */
    val onHome: (() -> Unit)?,
    val onSection: (Section) -> Unit,
    val onSearch: (scope: String?) -> Unit,
    val onMoreDrives: () -> Unit,
    val onNew: (NewChoice) -> Unit,
    val onProfile: () -> Unit,
    val onSettings: () -> Unit,
    val onCloseSidebar: () -> Unit,
)

/**
 * The one row at the bottom of the app, within the thumb's reach and the same on
 * every page (Flutter's `AppBottomBar`): Home, Search and New share one hold
 * menu ([HoldMenu]: a swipe opens it at once, a still finger after 150 ms, a quick
 * tap is the button's action), then the person (avatar and name) and Settings.
 * Next to the pages ([split]) the bar is the foot of the sidebar: six equal
 * slots, the last one closing the sidebar. The button of the page on top is
 * drawn in the main colour and does nothing.
 */
@Composable
fun BottomBar(
    split: Boolean,
    current: BarPage,
    sections: List<Section>,
    drives: List<DriveRow>,
    identity: Identity?,
    actions: BarActions,
    modifier: Modifier = Modifier,
) {
    val atomic = MaterialTheme.atomic
    Column(modifier.fillMaxWidth().background(atomic.bg1).testTag("bottom-bar")) {
        Box(Modifier.fillMaxWidth().height(1.dp).background(MaterialTheme.colorScheme.outlineVariant))
        Box(Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 8.dp).height(BAR_ROW_HEIGHT), contentAlignment = Alignment.Center) {
            BoxWithConstraints(Modifier.widthIn(max = MAX_BUTTONS_WIDTH)) {
                // Room for the name next to the avatar: a wide window, not a phone.
                val roomy = maxWidth + 16.dp >= 400.dp
                val buttons: List<@Composable () -> Unit> = listOf<@Composable () -> Unit>(
                    {
                        BarSlot("Home", current == BarPage.Home) {
                            HoldMenu(
                                items = sections.map { HoldItem(it.title, it, sectionIcon(it)) },
                                onSelected = actions.onSection,
                                onTap = actions.onHome,
                            ) { BarIcon(if (current == BarPage.Home) Icons.Filled.Home else Icons.Outlined.Home, current == BarPage.Home) }
                        }
                    },
                    {
                        BarSlot("Search", current == BarPage.Search) {
                            val items = buildList {
                                add(HoldItem("All drives", ALL_DRIVES, Icons.Outlined.Search))
                                drives.take(LIST_DRIVES).forEach { add(HoldItem(it.name.ifEmpty { "Untitled drive" }, it.subject, emoji = it.emoji)) }
                                if (drives.size > LIST_DRIVES) add(HoldItem("More…", MORE_DRIVES, Icons.Outlined.MoreHoriz))
                            }
                            HoldMenu(
                                items = items,
                                onSelected = { v -> when (v) { ALL_DRIVES -> actions.onSearch(null); MORE_DRIVES -> actions.onMoreDrives(); else -> actions.onSearch(v) } },
                                onTap = { actions.onSearch(null) },
                            ) { BarIcon(Icons.Outlined.Search, current == BarPage.Search) }
                        }
                    },
                    {
                        BarSlot("New", current == BarPage.New) {
                            HoldMenu(items = newItems, onSelected = actions.onNew, tapOpensMenu = true) {
                                BarIcon(Icons.Outlined.Add, current == BarPage.New)
                            }
                        }
                    },
                    {
                        BarSlot("Profile", current == BarPage.Profile) {
                            ProfileButton(identity, current == BarPage.Profile, wide = roomy && !split, onClick = actions.onProfile)
                        }
                    },
                    {
                        BarSlot("Settings", current == BarPage.Settings) {
                            BarButton(Icons.Outlined.Settings, "Settings", current == BarPage.Settings, actions.onSettings)
                        }
                    },
                ) + if (split) listOf<@Composable () -> Unit>({
                    BarSlot("Close sidebar", false) { BarButton(CloseSidebarIcon, "Close sidebar", false, actions.onCloseSidebar) }
                }) else emptyList()
                if (split) {
                    // Six equal slots across the sidebar, which fit its narrowest width too.
                    Row(Modifier.fillMaxWidth()) { buttons.forEach { Box(Modifier.weight(1f), contentAlignment = Alignment.Center) { it() } } }
                } else {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly, verticalAlignment = Alignment.CenterVertically) {
                        buttons.forEach { it() }
                    }
                }
            }
        }
    }
}

/** Marks a slot as the current one for accessibility and for tests. */
@Composable
private fun BarSlot(label: String, current: Boolean, content: @Composable () -> Unit) {
    Box(Modifier.semantics { selected = current; contentDescription = label }.testTag("bar-$label"), contentAlignment = Alignment.Center) { content() }
}

@Composable
private fun BarIcon(icon: ImageVector, current: Boolean) {
    Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
        Icon(icon, contentDescription = null, tint = if (current) MaterialTheme.atomic.main else MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun BarButton(icon: ImageVector, label: String, current: Boolean, onClick: () -> Unit) {
    Box(
        Modifier.size(48.dp).clickable(enabled = !current, role = Role.Button, onClickLabel = label, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) { Icon(icon, contentDescription = label, tint = if (current) MaterialTheme.atomic.main else MaterialTheme.colorScheme.onSurfaceVariant) }
}

/** The widest the name next to the avatar gets. */
private val PROFILE_NAME_WIDTH = 96.dp

/**
 * The profile button: the person's avatar (ringed in the main colour when their
 * page is on top) and, on a wide bar, their name; a person icon until the
 * identity is loaded. As big as the bar's icons (24 dp). Neutral unless the
 * profile is the page shown.
 */
@Composable
private fun ProfileButton(identity: Identity?, current: Boolean, wide: Boolean, onClick: () -> Unit) {
    val atomic = MaterialTheme.atomic
    if (identity == null) {
        BarButton(Icons.Outlined.Person, "Profile", current, onClick)
        return
    }
    val name = identity.name.trim()
    Row(
        Modifier.height(48.dp).widthIn(min = 48.dp).clickable(enabled = !current, role = Role.Button, onClickLabel = name.ifEmpty { "Profile" }, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        Box(Modifier.padding(horizontal = 4.dp).size(28.dp).border(2.dp, if (current) atomic.main else androidx.compose.ui.graphics.Color.Transparent, CircleShape), contentAlignment = Alignment.Center) {
            ProfileAvatar(
                name, emoji = identity.emoji, image = identity.image, size = 24.dp,
                background = if (current) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                foreground = if (current) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (wide && name.isNotEmpty()) {
            Text(
                name, Modifier.padding(start = 2.dp, end = 4.dp).widthIn(max = PROFILE_NAME_WIDTH), maxLines = 1, overflow = TextOverflow.Ellipsis,
                color = if (current) atomic.main else MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 14.sp,
            )
        }
    }
}
