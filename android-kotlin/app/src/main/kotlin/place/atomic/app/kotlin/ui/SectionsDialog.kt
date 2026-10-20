package place.atomic.app.kotlin.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DragHandle
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import place.atomic.app.kotlin.data.HomeLayout

private val ROW_HEIGHT = 52.dp

/**
 * The Home sections dialog (Flutter's `HomeSectionsDialog`): a checkbox shows or
 * hides each section, the handle drags it to its place, Reset puts the default
 * back. A bottom sheet on a phone, a card of at most 420 dp on a tablet. Every
 * change is kept at once.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SectionsDialog(layout: HomeLayout, onChange: (HomeLayout) -> Unit, onDone: () -> Unit, wide: Boolean) {
    if (wide) {
        Dialog(onDismissRequest = onDone) {
            Surface(Modifier.widthIn(max = 420.dp), shape = RoundedCornerShape(24.dp), color = MaterialTheme.colorScheme.surface) {
                SectionsContent(layout, onChange, onDone)
            }
        }
    } else {
        ModalBottomSheet(onDismissRequest = onDone) { SectionsContent(layout, onChange, onDone, Modifier.navigationBarsPadding()) }
    }
}

@Composable
fun SectionsContent(layout: HomeLayout, onChange: (HomeLayout) -> Unit, onDone: () -> Unit, modifier: Modifier = Modifier) {
    val rowPx = with(LocalDensity.current) { ROW_HEIGHT.toPx() }
    val current by rememberUpdatedState(layout)
    Column(modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag("sections-dialog")) {
        Text("Home sections", style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(vertical = 12.dp))
        layout.order.forEach { section ->
            var dragged by remember { mutableFloatStateOf(0f) }
            Row(Modifier.fillMaxWidth().height(ROW_HEIGHT).testTag("sections-row-${section.name}"), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(section !in layout.hidden, { onChange(layout.setHidden(section, it.not())) })
                Text(section.title, Modifier.weight(1f).padding(start = 4.dp))
                Box(
                    Modifier
                        .size(48.dp)
                        .pointerInput(section) {
                            detectDragGestures(onDragEnd = { dragged = 0f }, onDragCancel = { dragged = 0f }) { change, drag ->
                                change.consume()
                                dragged += drag.y
                                // One row further than half its height: it swaps with its neighbour.
                                val at = current.order.indexOf(section)
                                val step = when {
                                    dragged > rowPx / 2 && at < current.order.lastIndex -> 1
                                    dragged < -rowPx / 2 && at > 0 -> -1
                                    else -> 0
                                }
                                if (step != 0) {
                                    onChange(current.reorder(at, at + step))
                                    dragged -= step * rowPx
                                }
                            }
                        }
                        .testTag("sections-handle-${section.name}"),
                    contentAlignment = Alignment.Center,
                ) { Icon(Icons.Outlined.DragHandle, contentDescription = "Move ${section.title}", tint = MaterialTheme.atomic.textSecondary) }
            }
        }
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.SpaceBetween) {
            TextButton({ onChange(layout.reset()) }) { Text("Reset to default") }
            TextButton(onDone) { Text("Done") }
        }
    }
}
