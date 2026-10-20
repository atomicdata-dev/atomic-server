package place.atomic.app.kotlin.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.core.OwnProfile
import place.atomic.app.kotlin.errorText

/** Name and description of the agent (Flutter's `EditProfileScreen`). The picture is not editable here. */
@Composable
fun EditProfileScreen(profile: OwnProfile, save: suspend (name: String, description: String) -> Unit, onDone: () -> Unit, image: ByteArray? = null) {
    var name by rememberSaveable { mutableStateOf(profile.name) }
    var description by rememberSaveable { mutableStateOf(profile.description) }
    var saving by rememberSaveable { mutableStateOf(false) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val canSave = name.isNotBlank() && !saving

    AtomicScaffold("Profile", onDone, actions = {
        TextButton(
            {
                saving = true
                error = null
                scope.launch {
                    try {
                        save(name, description)
                        onDone()
                    } catch (e: Exception) {
                        error = errorText(e)
                        saving = false
                    }
                }
            },
            enabled = canSave,
            modifier = Modifier.testTag("save-profile"),
        ) { if (saving) Spinner(size = 16.dp) else Text("Save") }
    }) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ProfileAvatar(name, Modifier.align(Alignment.CenterHorizontally), emoji = profile.emoji, image = image, size = 88.dp)
            OutlinedTextField(
                name, { name = it }, Modifier.fillMaxWidth().padding(top = 8.dp).testTag("profile-name"),
                label = { Text("Name") }, singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.Words),
            )
            OutlinedTextField(
                description, { description = it }, Modifier.fillMaxWidth().testTag("profile-description"),
                label = { Text("Description") }, minLines = 3, maxLines = 6,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
            )
            error?.let { ErrorBox(it) }
            Text(
                "Others see this name and description wherever you show up: in chats, comments and the history of what you edit.",
                color = MaterialTheme.atomic.textSecondary, fontSize = 13.sp,
            )
        }
    }
}
