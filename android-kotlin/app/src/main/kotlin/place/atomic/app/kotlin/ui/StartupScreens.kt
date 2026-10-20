package place.atomic.app.kotlin.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Healing
import androidx.compose.material.icons.outlined.IosShare
import androidx.compose.material.icons.outlined.ReportProblem
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import place.atomic.app.kotlin.core.StoreRecovery
import java.io.File

@Composable
private fun NoticePage(icon: ImageVector, error: Boolean, title: String, body: String, content: @Composable () -> Unit) {
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Icon(icon, null, Modifier.size(48.dp), tint = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(16.dp))
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))
        Text(body, style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.height(24.dp))
        content()
    }
}

@Composable
private fun Details(text: String) {
    Spacer(Modifier.height(16.dp))
    SelectionContainer { Text(text, style = MaterialTheme.typography.bodySmall) }
}

/** Shown once, before anything else, when a damaged store was set aside. The file is never deleted. */
@Composable
fun StoreRecoveryScreen(notice: StoreRecovery, onContinue: () -> Unit) {
    val context = LocalContext.current
    var shareError by rememberSaveable { mutableStateOf<String?>(null) }
    NoticePage(
        icon = if (notice.repaired) Icons.Outlined.Healing else Icons.Outlined.ReportProblem,
        error = false,
        title = if (notice.repaired) "Your local data was repaired" else "Your local data could not be opened",
        body = if (notice.repaired) {
            "The app was closed while it was saving, and the data on this device was damaged. " +
                "It has been repaired; the last changes before the app closed may be missing. " +
                "Changes that reached a server or a paired device come back when they sync."
        } else {
            "The app was closed while it was saving, and the data on this device was damaged beyond repair. " +
                "The app starts with an empty local copy. Your identity is kept, so you stay signed in, " +
                "and your drives come back from your server or paired devices when they sync. " +
                "Anything that only existed on this device is in the damaged file, which is kept."
        },
    ) {
        Button(onContinue, Modifier.fillMaxWidth().testTag("store-recovery-continue")) { Text(if (notice.repaired) "Continue" else "Start fresh") }
        Spacer(Modifier.height(8.dp))
        OutlinedButton({ shareError = shareFile(context, notice.keptPath) }, Modifier.fillMaxWidth().testTag("store-recovery-share")) {
            Icon(Icons.Outlined.IosShare, null, Modifier.size(18.dp))
            Text("Share the damaged file", Modifier.padding(start = 8.dp))
        }
        shareError?.let { Details("Could not share the file: $it") }
        Details("Details\n${notice.reason}\n\nKept at ${notice.keptPath}")
    }
}

/** Opens the share sheet for the kept file; returns an error text, or `null`. */
private fun shareFile(context: Context, path: String): String? = try {
    val file = File(path)
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.files", file)
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "application/octet-stream"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(send, "Share the damaged file").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    null
} catch (e: Exception) {
    e.message ?: e.toString()
}

/** The local data could not be opened at all and nothing was changed (permissions, a full disk). */
@Composable
fun StoreOpenFailedScreen(error: String, onRetry: () -> Unit) {
    NoticePage(
        icon = Icons.Outlined.Storage,
        error = true,
        title = "The app could not open its local data",
        body = "Nothing was changed or deleted. This can happen when the device is out of storage. " +
            "Free some space and try again, or restart the app.",
    ) {
        Button(onRetry, Modifier.fillMaxWidth().testTag("store-open-retry")) { Text("Try again") }
        Details(error)
    }
}

/** Anything else that stopped the app from starting. */
@Composable
fun StartupFailedScreen(error: String, onRetry: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var copied by rememberSaveable { mutableStateOf(false) }
    NoticePage(
        icon = Icons.Outlined.ErrorOutline,
        error = true,
        title = "The app could not start",
        body = "Nothing was changed or deleted. Try again, or restart the app. " +
            "If this keeps happening, copy the details and send them to us.",
    ) {
        Button(onRetry, Modifier.fillMaxWidth().testTag("startup-retry")) { Text("Try again") }
        Spacer(Modifier.height(8.dp))
        OutlinedButton({
            clipboard.setText(AnnotatedString(error))
            copied = true
        }, Modifier.fillMaxWidth().testTag("startup-copy")) { Text(if (copied) "Copied" else "Copy details") }
        Details(error)
    }
}
