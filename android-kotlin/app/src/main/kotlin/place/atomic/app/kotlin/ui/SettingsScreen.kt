package place.atomic.app.kotlin.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.CloudDone
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Logout
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.QrCode2
import androidx.compose.material.icons.outlined.RadioButtonChecked
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import kotlinx.coroutines.launch
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.data.ServerRow
import place.atomic.app.kotlin.data.SettingsState
import place.atomic.app.kotlin.data.isServerPeer
import place.atomic.app.kotlin.data.usageLine
import place.atomic.app.kotlin.session.serverLabel

class SettingsActions(
    val onBack: () -> Unit,
    val onEditProfile: () -> Unit,
    val onRename: (String) -> Unit,
    val onNewWorkspace: (String) -> Unit,
    val onSwitchDrive: (String) -> Unit,
    val onSwitchServer: (String) -> Unit,
    val onAddServer: (String) -> Unit,
    val onRemoveServer: (String) -> Unit,
    val onPush: () -> Unit,
    val onRemovePeer: (String) -> Unit,
    val onPair: () -> Unit,
    val onMessageShown: () -> Unit,
    val secret: () -> String?,
    val onSignOut: () -> Unit,
)

private enum class Ask { None, Rename, NewWorkspace, AddServer, SignOut, Workspaces }

/**
 * Your agent and everything that syncs, after Flutter's `SyncScreen` and the
 * devices section it embeds: who you are, the workspace, this device, the
 * always-on devices (servers) and the paired devices, and pairing.
 */
@Composable
fun SettingsScreen(state: SettingsState, actions: SettingsActions) {
    val clipboard = LocalClipboardManager.current
    val snackbar = remember { SnackbarHostState() }
    var ask by rememberSaveable { mutableStateOf(Ask.None) }
    var addingServer by rememberSaveable { mutableStateOf(false) }

    fun copy(text: String, what: String, say: (String) -> Unit) {
        clipboard.setText(AnnotatedString(text))
        say("$what copied")
    }
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbar.showSnackbar(it)
            actions.onMessageShown()
        }
    }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val say: (String) -> Unit = { text -> scope.launch { snackbar.showSnackbar(text) } }

    AtomicScaffold("Sync", actions.onBack, snackbarHost = { SnackbarHost(snackbar) }) { padding ->
        if (state.loading) {
            FullScreenMessage(Modifier.padding(padding)) { Spinner(size = 32.dp) }
            return@AtomicScaffold
        }
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 32.dp),
        ) {
            state.error?.let { ErrorBox(it, Modifier.padding(bottom = 12.dp)) }

            // Who you are
            val name = state.profile?.name.orEmpty()
            Row(
                Modifier.fillMaxWidth().clickable(onClick = actions.onEditProfile).padding(vertical = 4.dp).testTag("profile"),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                ProfileAvatar(name, emoji = state.profile?.emoji, image = state.profileImage, size = 56.dp)
                Column(Modifier.weight(1f)) {
                    Text(name.ifEmpty { "You" }, style = MaterialTheme.typography.titleLarge)
                    state.profile?.subject?.let { id ->
                        Row(
                            Modifier.clickable { copy(id, "Agent ID", say) }.padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(shortId(id), color = MaterialTheme.atomic.textSecondary, fontSize = 12.sp, maxLines = 1, modifier = Modifier.weight(1f, fill = false))
                            Icon(Icons.Outlined.ContentCopy, "Copy ID", Modifier.padding(start = 6.dp).size(14.dp), tint = MaterialTheme.atomic.textSecondary)
                        }
                    }
                }
            }
            Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton({ actions.secret()?.let { copy(it, "Secret key", say) } }) {
                    Icon(Icons.Outlined.Key, null, Modifier.size(16.dp))
                    Text("Copy secret key", Modifier.padding(start = 8.dp))
                }
                OutlinedButton({ ask = Ask.SignOut }) {
                    Icon(Icons.Outlined.Logout, null, Modifier.size(16.dp))
                    Text("Sign out", Modifier.padding(start = 8.dp))
                }
            }

            // The workspace in use; a tap opens the switcher.
            Column(Modifier.padding(top = 16.dp)) {
                SettingsGroup("Workspace", Modifier.padding(top = 0.dp)) {
                    SettingsRow(
                        title = state.activeDrive?.let { d -> state.drives.firstOrNull { it.subject == d }?.name?.ifEmpty { null } ?: "Workspace" } ?: "No workspace",
                        icon = Icons.Outlined.FolderOpen,
                        subtitle = "Workspace",
                        trailing = { Icon(Icons.Outlined.ExpandMore, null, tint = MaterialTheme.atomic.textSecondary) },
                        onClick = { ask = Ask.Workspaces },
                        modifier = Modifier.testTag("workspace"),
                    )
                }
            }

            SettingsGroup("This device") {
                SettingsRow(
                    title = state.deviceName.ifEmpty { "This device" },
                    icon = Icons.Outlined.PhoneAndroid,
                    subtitle = listOfNotNull(
                        if (state.peerId != null) "Online" else "Offline",
                        state.peerId?.let(::shortId),
                    ).joinToString(" · "),
                    trailing = { Icon(Icons.Outlined.Edit, "Rename", Modifier.size(18.dp)) },
                    onClick = { ask = Ask.Rename },
                    modifier = Modifier.testTag("this-device"),
                )
            }

            Devices(state, actions, addingServer, onAdd = { addingServer = true }, onCloseAdd = { addingServer = false }, copy = { t, w -> copy(t, w, say) })
        }
    }

    when (ask) {
        Ask.Rename -> TextAsk("Device name", "Name this device", state.deviceName, "Save", { ask = Ask.None }) {
            actions.onRename(it); ask = Ask.None
        }
        Ask.NewWorkspace -> TextAsk("New workspace", "Name", "", "Save", { ask = Ask.None }) {
            actions.onNewWorkspace(it); ask = Ask.None
        }
        Ask.SignOut -> AtomicDialog("Sign out?", { ask = Ask.None }, "Sign out", { ask = Ask.None; actions.onSignOut() }) {
            Text("Your data stays on this device, but you'll need your secret key to sign back in.")
        }
        Ask.Workspaces -> WorkspacePicker(state, onPick = { ask = Ask.None; actions.onSwitchDrive(it) }, onNew = { ask = Ask.NewWorkspace }, onDismiss = { ask = Ask.None })
        else -> {}
    }
}

private fun shortId(id: String) = if (id.length <= 22) id else "${id.take(12)}…${id.takeLast(6)}"

@Composable
private fun TextAsk(title: String, hint: String, initial: String, confirm: String, onDismiss: () -> Unit, onDone: (String) -> Unit) {
    var text by rememberSaveable { mutableStateOf(initial) }
    AtomicDialog(title, onDismiss, confirm, { onDone(text.trim()) }, confirmEnabled = text.isNotBlank()) {
        OutlinedTextField(text, { text = it }, placeholder = { Text(hint) }, singleLine = true)
    }
}

/** The workspaces on this device, each once; those listed but not received are one line, not forty. */
@Composable
private fun WorkspacePicker(state: SettingsState, onPick: (String) -> Unit, onNew: () -> Unit, onDismiss: () -> Unit) {
    val seen = mutableSetOf<String>()
    val shown = mutableListOf<place.atomic.app.kotlin.core.DriveRow>()
    var elsewhere = 0
    for (d in state.drives) {
        if (!seen.add(d.subject.removePrefix("did:ad:").removePrefix("atomic:").substringBefore('?'))) continue
        if (d.name.isNotEmpty() || d.subject == state.activeDrive) shown += d else elsewhere++
    }
    AtomicDialog("Workspace", onDismiss, "New workspace", onNew) {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            for (d in shown) {
                SettingsRow(
                    d.name.ifEmpty { "Workspace" },
                    icon = if (d.subject == state.activeDrive) Icons.Outlined.RadioButtonChecked else Icons.Outlined.RadioButtonUnchecked,
                    onClick = { onPick(d.subject) },
                )
            }
            if (elsewhere > 0) {
                SettingsRow(
                    "$elsewhere more workspace${if (elsewhere == 1) "" else "s"} not on this device yet",
                    icon = Icons.Outlined.Cloud,
                )
            }
        }
    }
}

@Composable
private fun Devices(
    state: SettingsState,
    actions: SettingsActions,
    adding: Boolean,
    onAdd: () -> Unit,
    onCloseAdd: () -> Unit,
    copy: (String, String) -> Unit,
) {
    val atomic = MaterialTheme.atomic
    Column(Modifier.padding(top = 20.dp)) {
        Text("Devices", Modifier.padding(start = 16.dp, bottom = 8.dp), color = atomic.textSecondary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
        // The sync status in one line: is a server session open, how many devices answer.
        Text(
            listOf(
                if (state.serverConnected) "Connected to a server" else "No server connected",
                when (val n = state.livePeers) { 0 -> "no device online"; 1 -> "1 device online"; else -> "$n devices online" },
            ).joinToString(" · "),
            Modifier.padding(start = 16.dp, bottom = 8.dp).testTag("sync-status"),
            color = atomic.textSecondary,
            fontSize = 12.sp,
        )
        if (state.servers.isEmpty() && state.peers.isEmpty()) {
            Text("No other devices yet. Pair one below, or add an always-on device by address.", Modifier.padding(start = 16.dp, bottom = 8.dp), color = atomic.textSecondary, fontSize = 12.sp)
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            for (server in state.servers) ServerCard(server, state, actions, copy)
            for (peer in state.peers) {
                if (state.servers.none { isServerPeer(it, peer) }) PeerCard(peer, actions, copy)
            }
        }
        if (adding) {
            AddServer(onAdd = { actions.onAddServer(it); onCloseAdd() }, onCancel = onCloseAdd)
        } else {
            Row(Modifier.padding(top = 4.dp)) {
                TextButton(actions.onPair, Modifier.testTag("pair")) {
                    Icon(Icons.Outlined.QrCode2, null, Modifier.size(16.dp))
                    Text("Pair with QR code", Modifier.padding(start = 8.dp), fontSize = 12.sp)
                }
                TextButton(onAdd) {
                    Icon(Icons.Outlined.Add, null, Modifier.size(16.dp))
                    Text("Connect by address", Modifier.padding(start = 8.dp), fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
private fun ServerCard(server: ServerRow, state: SettingsState, actions: SettingsActions, copy: (String, String) -> Unit) {
    val atomic = MaterialTheme.atomic
    val peer = state.peers.firstOrNull { isServerPeer(server, it) }
    Card(highlight = server.active) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(if (server.active) Icons.Outlined.CloudDone else Icons.Outlined.Cloud, null, Modifier.size(18.dp), tint = if (server.active) atomic.main else atomic.textSecondary)
            Text(serverLabel(server.url), Modifier.padding(start = 8.dp).weight(1f), fontWeight = if (server.active) FontWeight.SemiBold else FontWeight.Normal, maxLines = 1)
            if (server.active) Pill("In use", atomic.main)
        }
        if (server.active) {
            if (state.busy) {
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
            } else {
                Row(Modifier.padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    val version = server.info?.version
                    Text(
                        if (version != null) "atomic-server $version" else "Not reachable",
                        Modifier.weight(1f), fontSize = 11.sp,
                        color = if (version != null) atomic.textSecondary else atomic.alert,
                    )
                    server.info?.nodeId?.let { id -> TextButton({ copy(id, "Node ID") }) { Text("Copy ID", fontSize = 11.sp) } }
                }
                server.usage?.let { u ->
                    Text(usageLine(u), fontSize = 11.sp, color = atomic.textSecondary)
                    if (u.blobBytes > 0u) Text("files ${place.atomic.app.kotlin.data.formatBytes(u.blobBytes.toLong())} · edits ${place.atomic.app.kotlin.data.formatBytes(u.loroBytes.toLong())}", fontSize = 10.sp, color = atomic.textSecondary)
                }
            }
        }
        peer?.let {
            Text(
                listOfNotNull(if (it.live) "Connected" else "Paired", it.lastSynced?.let { t -> "last synced ${timeAgo(t.toLong())}" }).joinToString(" · "),
                Modifier.padding(top = 6.dp), fontSize = 11.sp, color = atomic.textSecondary,
            )
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            if (server.active) {
                TextButton(actions.onPush, enabled = !state.busy) { Text("Sync workspace here", fontSize = 12.sp) }
            } else {
                TextButton({ actions.onSwitchServer(server.url) }, enabled = !state.busy) { Text("Switch to this", fontSize = 12.sp) }
            }
            TextButton({ actions.onRemoveServer(server.url) }, enabled = !state.busy) { Text("Remove", fontSize = 12.sp, color = atomic.alert) }
        }
    }
}

@Composable
private fun PeerCard(peer: place.atomic.app.kotlin.core.PeerRow, actions: SettingsActions, copy: (String, String) -> Unit) {
    val atomic = MaterialTheme.atomic
    Card(highlight = false) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Outlined.PhoneAndroid, null, Modifier.size(18.dp), tint = atomic.textSecondary)
            Text(peer.name.trim().ifEmpty { peer.nodeId.take(12) + "…" }, Modifier.padding(start = 8.dp).weight(1f), maxLines = 1)
            Pill(if (peer.live) "Connected" else "Paired", if (peer.live) atomic.success else atomic.textSecondary)
            IconButton({ actions.onRemovePeer(peer.nodeId) }, Modifier.size(28.dp)) { Icon(Icons.Outlined.Close, "Remove", Modifier.size(16.dp)) }
        }
        Row(Modifier.padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                peer.lastSynced?.let { "Last synced ${timeAgo(it.toLong())}" } ?: "Not synced yet",
                Modifier.weight(1f), fontSize = 11.sp, color = atomic.textSecondary,
            )
            if (peer.nodeId.isNotEmpty()) TextButton({ copy(peer.nodeId, "Device ID") }) { Text("Copy ID", fontSize = 11.sp) }
        }
    }
}

@Composable
private fun Card(highlight: Boolean, content: @Composable () -> Unit) {
    val atomic = MaterialTheme.atomic
    Column(
        Modifier
            .fillMaxWidth()
            .clip(androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
            .border(if (highlight) 1.5.dp else 1.dp, if (highlight) atomic.main else atomic.border, androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
            .padding(12.dp),
    ) { content() }
}

@Composable
private fun Pill(text: String, color: androidx.compose.ui.graphics.Color) {
    Text(
        text, fontSize = 10.sp, color = color,
        modifier = Modifier.border(1.dp, color, androidx.compose.foundation.shape.RoundedCornerShape(10.dp)).padding(horizontal = 8.dp, vertical = 2.dp),
    )
}

@Composable
private fun AddServer(onAdd: (String) -> Unit, onCancel: () -> Unit) {
    var address by rememberSaveable { mutableStateOf("") }
    Row(Modifier.padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            address, { address = it },
            Modifier.weight(1f).widthIn(min = 120.dp).testTag("server-address"),
            placeholder = { Text("localhost:9883") },
            singleLine = true,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
        )
        TextButton({ onAdd(address) }, enabled = address.isNotBlank()) { Text("Add") }
        TextButton(onCancel) { Text("Cancel") }
    }
}
