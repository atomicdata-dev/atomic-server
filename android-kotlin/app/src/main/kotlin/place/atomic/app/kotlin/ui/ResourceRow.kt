package place.atomic.app.kotlin.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import place.atomic.app.kotlin.data.RowItem

/**
 * One line of any list of resources (Flutter's `ResourceRow`): the resource's
 * own emoji, else the icon of its class, a title, a line of detail and
 * something at the end (when it happened).
 */
@Composable
fun ResourceRow(item: RowItem, onClick: () -> Unit, modifier: Modifier = Modifier, end: (@Composable () -> Unit)? = null) {
    val atomic = MaterialTheme.atomic
    Row(
        modifier
            .fillMaxWidth()
            .clickable(enabled = item.openable, onClick = onClick)
            .heightIn(min = if (item.detail.isEmpty()) 52.dp else 64.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // The icon box is 24 dp either way, so rows line up.
        Box(Modifier.size(24.dp), contentAlignment = Alignment.Center) {
            if (!item.emoji.isNullOrEmpty()) {
                Text(item.emoji, fontSize = 20.sp, lineHeight = 20.sp)
            } else {
                Icon(iconForClass(item.className), contentDescription = null, tint = atomic.main)
            }
        }
        Column(Modifier.weight(1f)) {
            Text(item.title, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (item.detail.isNotEmpty()) {
                Text(
                    item.detail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = atomic.textSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (item.trailing.isNotEmpty()) {
            Text(item.trailing, color = atomic.textSecondary, fontSize = 12.sp, maxLines = 1)
        }
        end?.invoke()
    }
}
