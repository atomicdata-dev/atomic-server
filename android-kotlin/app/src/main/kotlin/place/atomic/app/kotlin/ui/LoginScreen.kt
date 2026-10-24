package place.atomic.app.kotlin.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.SyncProblem
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.AppState
import place.atomic.app.kotlin.LoginUi

private enum class Step { Welcome, Create, SignIn }

/** What the login screens do; the screen only draws. */
class LoginActions(
    val onCreate: (name: String) -> Unit,
    val onSignIn: (secret: String) -> Unit,
    val onSecretSaved: () -> Unit,
    val onFindDrive: () -> Unit,
    /** Opens the pairing screen; with a node id when one was pasted. */
    val onPair: (nodeId: String?) -> Unit,
    /** The node id in a pasted code, `null` when it is not one. */
    val nodeIdOf: (String) -> String?,
    val onBack: () -> Unit,
)

/**
 * First run and sign-in (Flutter's `LoginScreen`): welcome, create an identity,
 * the secret to save, sign in with a secret, and "sync your drive" for a drive
 * that is not on this device yet. Signing in with an atomic.place account is not
 * built.
 */
@Composable
fun LoginScreen(state: AppState, ui: LoginUi, actions: LoginActions) {
    var step by rememberSaveable { mutableStateOf(Step.Welcome) }
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
    ) {
        when {
            state is AppState.ShowSecret -> ShowSecret(state.secret, actions.onSecretSaved)
            state is AppState.NeedsSync -> NeedsSync(ui, actions)
            step == Step.Welcome -> Welcome(ui, onStart = { step = Step.Create }, onSignIn = { step = Step.SignIn })
            step == Step.Create -> Create(ui, onBack = { step = Step.Welcome }, onCreate = actions.onCreate)
            else -> SignIn(ui, onBack = { step = Step.Welcome }, onSignIn = actions.onSignIn)
        }
    }
}

@Composable
private fun Heading(text: String) = Text(text, fontSize = 22.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())

@Composable
private fun Note(text: String, center: Boolean = false) = Text(
    text,
    color = MaterialTheme.atomic.textSecondary,
    fontSize = 14.sp,
    textAlign = if (center) TextAlign.Center else TextAlign.Start,
    modifier = Modifier.fillMaxWidth(),
)

@Composable
private fun TitleRow(title: String, onBack: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back") }
        Text(title, fontSize = 20.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun Welcome(ui: LoginUi, onStart: () -> Unit, onSignIn: () -> Unit) {
    Text("atomic", fontSize = 40.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
    Note("Your data stays on this device.\nSync with others when you choose to.", center = true)
    Button(onStart, Modifier.fillMaxWidth().padding(top = 28.dp).testTag("get-started")) { Text("Get Started") }
    OutlinedButton(onSignIn, Modifier.fillMaxWidth().testTag("have-secret")) { Text("I have a secret — Sign In") }
    ui.error?.let { ErrorBox(it) }
}

@Composable
private fun Create(ui: LoginUi, onBack: () -> Unit, onCreate: (String) -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    TitleRow("Create your identity", onBack)
    Note("This creates a cryptographic identity and a personal drive to store your data.")
    // No sync address here: a new identity has no data anywhere to go and find.
    OutlinedTextField(name, { name = it }, Modifier.fillMaxWidth().padding(top = 12.dp), label = { Text("Your name") }, singleLine = true)
    Button({ onCreate(name) }, Modifier.fillMaxWidth(), enabled = !ui.busy) {
        if (ui.busy) Spinner() else Text("Create")
    }
    ui.error?.let { ErrorBox(it) }
}

@Composable
private fun ColumnScope.ShowSecret(secret: String, onContinue: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var copied by rememberSaveable { mutableStateOf(false) }
    Icon(Icons.Outlined.CheckCircle, null, Modifier.size(48.dp).align(Alignment.CenterHorizontally), tint = MaterialTheme.atomic.success)
    Heading("You're all set!")
    Column(
        Modifier.fillMaxWidth().padding(top = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Save this secret: it is the only way to sign in as you on another device.", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
        Text(secret, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.testTag("secret"))
        OutlinedButton({
            clipboard.setText(AnnotatedString(secret))
            copied = true
        }) {
            Icon(Icons.Outlined.ContentCopy, null, Modifier.size(16.dp))
            Text(if (copied) "Copied to clipboard" else "Copy secret", Modifier.padding(start = 8.dp))
        }
    }
    Button(onContinue, Modifier.fillMaxWidth().padding(top = 12.dp).testTag("continue")) { Text("Continue") }
}

@Composable
private fun SignIn(ui: LoginUi, onBack: () -> Unit, onSignIn: (String) -> Unit) {
    val clipboard = LocalClipboardManager.current
    var secret by rememberSaveable { mutableStateOf("") }
    // A secret is hidden by default: it is a password. The toggle checks what was pasted.
    var hidden by rememberSaveable { mutableStateOf(true) }
    TitleRow("Sign in", onBack)
    Note("Paste your secret to restore your identity.")
    // Signing in restores who you are. Where your data is, is the next screen's
    // question, and only if it turns out not to be here.
    OutlinedTextField(
        secret, { secret = it },
        Modifier.fillMaxWidth().padding(top = 12.dp).testTag("secret-input"),
        label = { Text("Your secret") },
        singleLine = true,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        visualTransformation = if (hidden) PasswordVisualTransformation() else VisualTransformation.None,
        trailingIcon = {
            IconButton({ hidden = !hidden }) {
                Icon(if (hidden) Icons.Outlined.Visibility else Icons.Outlined.VisibilityOff, if (hidden) "Show" else "Hide")
            }
        },
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button({ onSignIn(secret) }, Modifier.weight(1f), enabled = !ui.busy) {
            if (ui.busy) Spinner() else Text("Sign In")
        }
        // Paste and go: the secret lives on another device's clipboard, so one tap pastes it and signs in.
        OutlinedButton({
            val pasted = clipboard.getText()?.text?.trim().orEmpty()
            secret = pasted
            onSignIn(pasted)
        }, enabled = !ui.busy) {
            Icon(Icons.Outlined.ContentPaste, null, Modifier.size(18.dp))
            Text("Paste", Modifier.padding(start = 8.dp))
        }
    }
    ui.error?.let { ErrorBox(it) }
}

@Composable
private fun ColumnScope.NeedsSync(ui: LoginUi, actions: LoginActions) {
    val clipboard = LocalClipboardManager.current
    var pasting by rememberSaveable { mutableStateOf(false) }
    // The drive is looked for as soon as this screen shows, on a screen built to wait.
    androidx.compose.runtime.LaunchedEffect(Unit) { actions.onFindDrive() }
    Icon(Icons.Outlined.SyncProblem, null, Modifier.size(48.dp).align(Alignment.CenterHorizontally), tint = MaterialTheme.atomic.alert)
    Heading("Sync your drive")
    Note(
        "This device does not have your drive yet. We look for other devices on the network, " +
            "or you can pair with QR or a node ID.",
        center = true,
    )
    ui.error?.let { ErrorBox(it) }
    Button(actions.onFindDrive, Modifier.fillMaxWidth().padding(top = 12.dp), enabled = !ui.busy) {
        if (ui.busy) Spinner() else Icon(Icons.Outlined.Sync, null, Modifier.size(18.dp))
        Text(if (ui.busy) ui.status ?: "Looking for your devices…" else "Try again", Modifier.padding(start = 8.dp))
    }
    OutlinedButton({ actions.onPair(null) }, Modifier.fillMaxWidth()) {
        Icon(Icons.Outlined.QrCodeScanner, null, Modifier.size(18.dp))
        Text("Pair with QR", Modifier.padding(start = 8.dp))
    }
    TextButton({ pasting = true }, Modifier.align(Alignment.CenterHorizontally)) {
        Icon(Icons.Outlined.ContentPaste, null, Modifier.size(18.dp))
        Text("Paste node ID", Modifier.padding(start = 8.dp))
    }
    OutlinedButton(actions.onBack, Modifier.fillMaxWidth()) { Text("Back") }
    if (pasting) {
        PasteNodeIdDialog(
            initial = clipboard.getText()?.text.orEmpty().takeIf { actions.nodeIdOf(it) != null }?.trim().orEmpty(),
            onDismiss = { pasting = false },
            onSubmit = { text -> actions.nodeIdOf(text)?.also(actions.onPair) != null },
        )
    }
}

/** For when no camera can see the other device's code: its node id, copied from its settings, pasted here. */
@Composable
fun PasteNodeIdDialog(initial: String, onDismiss: () -> Unit, onSubmit: (String) -> Boolean) {
    var text by rememberSaveable { mutableStateOf(initial) }
    var error by rememberSaveable { mutableStateOf(false) }
    AtomicDialog("Paste node ID", onDismiss, "Connect", onConfirm = { if (onSubmit(text)) onDismiss() else error = true }) {
        OutlinedTextField(
            text, { text = it; error = false },
            placeholder = { Text("did:ad:node:…") },
            isError = error,
            supportingText = if (error) ({ Text("Not a node ID") }) else null,
            singleLine = true,
        )
    }
}
