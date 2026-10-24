package place.atomic.app.kotlin.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.data.PairState

/**
 * Pair a device (Flutter's `PairScreen`): this device's code to show, the
 * camera to read theirs, and a way to paste their node id when no camera can
 * see it. `scanner` is injected so the screen can be drawn without a camera.
 */
@Composable
fun PairScreen(
    state: PairState,
    onCode: (String) -> Boolean,
    onRetry: () -> Unit,
    onClose: () -> Unit,
    scanner: @Composable (Modifier) -> Unit = { QrScanner(onCode = { onCode(it) }, modifier = it) },
) {
    val clipboard = LocalClipboardManager.current
    var pasting by rememberSaveable { mutableStateOf(false) }
    AtomicScaffold("Pair a device", onClose) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(24.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            when (state) {
                PairState.Loading -> Box(Modifier.height(200.dp), Alignment.Center) { Spinner(size = 32.dp) }
                is PairState.ShowCode -> {
                    Text("Pair Device", style = MaterialTheme.typography.titleMedium)
                    Text("Show your QR or scan theirs", fontSize = 13.sp, color = MaterialTheme.atomic.textSecondary, textAlign = TextAlign.Center)
                    val bitmap = remember(state.code) { qrBitmap(state.code).asImageBitmap() }
                    Box(Modifier.clip(RoundedCornerShape(10.dp)).background(Color.White).padding(10.dp)) {
                        Image(bitmap, "Your pairing code", Modifier.size(180.dp).testTag("qr"))
                    }
                    if (state.deviceName.isNotEmpty()) Text(state.deviceName, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    Box(Modifier.fillMaxWidth().height(200.dp).clip(RoundedCornerShape(8.dp))) { scanner(Modifier) }
                    TextButton({ pasting = true }) {
                        Icon(Icons.Outlined.ContentPaste, null, Modifier.size(18.dp))
                        Text("Paste node ID", Modifier.padding(start = 8.dp))
                    }
                    TextButton(onClose) { Text("Cancel") }
                }
                is PairState.Syncing -> Column(Modifier.height(200.dp), Arrangement.Center, Alignment.CenterHorizontally) {
                    Spinner(size = 32.dp)
                    Text("Connecting to ${state.label}", Modifier.padding(top = 16.dp), fontSize = 13.sp, color = MaterialTheme.atomic.textSecondary)
                }
                is PairState.Done -> {
                    Icon(Icons.Outlined.CheckCircle, null, Modifier.size(48.dp), tint = MaterialTheme.atomic.success)
                    Text("Paired with ${state.label}", style = MaterialTheme.typography.titleMedium)
                    Text(state.summary, fontSize = 13.sp, color = MaterialTheme.atomic.textSecondary)
                    Button(onClose, Modifier.padding(top = 16.dp).testTag("pair-done")) { Text("Done") }
                }
                is PairState.Failed -> {
                    Icon(Icons.Outlined.ErrorOutline, null, Modifier.size(48.dp), tint = MaterialTheme.atomic.alert)
                    Text("Connection Failed", style = MaterialTheme.typography.titleMedium)
                    Text(state.message, fontSize = 12.sp, color = MaterialTheme.atomic.alert, textAlign = TextAlign.Center)
                    TextButton({ clipboard.setText(AnnotatedString(state.message)) }) {
                        Icon(Icons.Outlined.ContentCopy, null, Modifier.size(16.dp))
                        Text("Copy error", Modifier.padding(start = 8.dp))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                        TextButton(onClose) { Text("Cancel") }
                        TextButton(onRetry, Modifier.testTag("pair-retry")) { Text("Retry") }
                    }
                }
            }
        }
    }
    if (pasting) {
        PasteNodeIdDialog(
            initial = clipboard.getText()?.text.orEmpty().trim(),
            onDismiss = { pasting = false },
            onSubmit = onCode,
        )
    }
}
