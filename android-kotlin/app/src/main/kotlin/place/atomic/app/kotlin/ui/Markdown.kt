package place.atomic.app.kotlin.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** The blocks of a Markdown text, as far as a chat answer needs: what the web app's chat shows. */
sealed interface MdBlock {
    data class Paragraph(val text: String) : MdBlock
    data class Heading(val level: Int, val text: String) : MdBlock
    data class Code(val lang: String, val text: String) : MdBlock
    data class Quote(val text: String) : MdBlock
    data class Item(val depth: Int, val marker: String, val text: String) : MdBlock
    data object Rule : MdBlock
    data class Table(val header: List<String>, val rows: List<List<String>>) : MdBlock
}

private val HEADING = Regex("""^(#{1,6})\s+(.*)$""")
private val RULE = Regex("""^\s*([-*_])(\s*\1){2,}\s*$""")
private val ITEM = Regex("""^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$""")
private val TABLE_SEPARATOR = Regex("""^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$""")

private fun cells(line: String) = line.trim().removePrefix("|").removeSuffix("|").split('|').map { it.trim() }

/**
 * Parses [source] into blocks. Tolerant while an answer streams in: an unclosed
 * code fence runs to the end, an unclosed `**` is text.
 */
fun parseMarkdown(source: String): List<MdBlock> {
    val lines = source.replace("\r\n", "\n").split('\n')
    val out = mutableListOf<MdBlock>()
    val paragraph = StringBuilder()
    fun flush() {
        if (paragraph.isNotEmpty()) out += MdBlock.Paragraph(paragraph.toString().trim())
        paragraph.setLength(0)
    }
    var i = 0
    while (i < lines.size) {
        val line = lines[i]
        val trimmed = line.trim()
        when {
            trimmed.startsWith("```") -> {
                flush()
                val lang = trimmed.removePrefix("```").trim()
                val body = mutableListOf<String>()
                i++
                while (i < lines.size && !lines[i].trim().startsWith("```")) body += lines[i++]
                out += MdBlock.Code(lang, body.joinToString("\n"))
            }
            trimmed.isEmpty() -> flush()
            HEADING.matches(trimmed) -> {
                flush()
                val m = HEADING.matchEntire(trimmed)!!
                out += MdBlock.Heading(m.groupValues[1].length, m.groupValues[2].trim().trimEnd('#').trim())
            }
            RULE.matches(line) -> {
                flush()
                out += MdBlock.Rule
            }
            trimmed.startsWith(">") -> {
                flush()
                val quoted = mutableListOf<String>()
                while (i < lines.size && lines[i].trim().startsWith(">")) quoted += lines[i++].trim().removePrefix(">").trim()
                i--
                out += MdBlock.Quote(quoted.joinToString("\n"))
            }
            ITEM.matches(line) -> {
                flush()
                val m = ITEM.matchEntire(line)!!
                val indent = m.groupValues[1].replace("\t", "    ").length
                val marker = m.groupValues[2].let { if (it[0].isDigit()) it else "•" }
                out += MdBlock.Item(indent / 2, marker, m.groupValues[3].trim())
            }
            '|' in line && i + 1 < lines.size && TABLE_SEPARATOR.matches(lines[i + 1]) -> {
                flush()
                val header = cells(line)
                i += 2
                val rows = mutableListOf<List<String>>()
                while (i < lines.size && '|' in lines[i] && lines[i].isNotBlank()) rows += cells(lines[i++])
                i--
                out += MdBlock.Table(header, rows)
            }
            else -> {
                if (paragraph.isNotEmpty()) paragraph.append(' ')
                paragraph.append(trimmed)
            }
        }
        i++
    }
    flush()
    return out
}

/** The look of inline Markdown. */
class MdStyle(val link: Color, val codeBackground: Color)

/**
 * Inline Markdown: `code`, **bold**, *italic*, [links](url). Anything unclosed
 * stays as typed, so a half-written answer reads right.
 */
fun inlineMarkdown(text: String, style: MdStyle, onLink: (String) -> Unit): AnnotatedString = buildAnnotatedString {
    appendInline(text, style, onLink)
}

private fun AnnotatedString.Builder.appendInline(text: String, style: MdStyle, onLink: (String) -> Unit) {
    var i = 0
    val plain = StringBuilder()
    fun flush() {
        if (plain.isNotEmpty()) append(plain.toString())
        plain.setLength(0)
    }
    while (i < text.length) {
        val c = text[i]
        val rest = text.substring(i)
        when {
            c == '`' && text.indexOf('`', i + 1) > i -> {
                flush()
                val end = text.indexOf('`', i + 1)
                withStyle(SpanStyle(fontFamily = FontFamily.Monospace, background = style.codeBackground, fontSize = 14.sp)) {
                    append(text.substring(i + 1, end))
                }
                i = end + 1
                continue
            }
            (rest.startsWith("**") || rest.startsWith("__")) && text.indexOf(rest.take(2), i + 2) > i + 2 -> {
                flush()
                val end = text.indexOf(rest.take(2), i + 2)
                withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { appendInline(text.substring(i + 2, end), style, onLink) }
                i = end + 2
                continue
            }
            (c == '*' || (c == '_' && (i == 0 || !text[i - 1].isLetterOrDigit()))) && text.indexOf(c, i + 1) > i + 1 &&
                !text[i + 1].isWhitespace() -> {
                flush()
                val end = text.indexOf(c, i + 1)
                withStyle(SpanStyle(fontStyle = FontStyle.Italic)) { appendInline(text.substring(i + 1, end), style, onLink) }
                i = end + 1
                continue
            }
            c == '[' -> {
                val mid = text.indexOf("](", i + 1)
                val close = if (mid > 0) text.indexOf(')', mid + 2) else -1
                if (mid > 0 && close > 0) {
                    flush()
                    val url = text.substring(mid + 2, close).trim()
                    withLink(
                        LinkAnnotation.Clickable(
                            tag = url,
                            styles = TextLinkStyles(SpanStyle(color = style.link, textDecoration = TextDecoration.Underline)),
                            linkInteractionListener = { onLink(url) },
                        ),
                    ) { appendInline(text.substring(i + 1, mid), style, onLink) }
                    i = close + 1
                    continue
                }
            }
        }
        plain.append(c)
        i++
    }
    flush()
}

/**
 * Markdown as a chat shows it: headings, emphasis, inline and fenced code (with
 * a copy button), lists, quotes, links (a resource opens in the app), tables and
 * rules. With [inline] only the inline marks are read, as for the person's own
 * messages. Re-parses on every change of [text]; the model hands over a growing
 * answer at most about 30 times a second.
 */
@Composable
fun MarkdownText(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.atomic.textPrimary,
    inline: Boolean = false,
    onLink: (String) -> Unit = {},
) {
    val atomic = MaterialTheme.atomic
    val style = MdStyle(link = atomic.main, codeBackground = atomic.border)
    val body = MaterialTheme.typography.bodyLarge
    if (inline) {
        Text(remember(text, style.link) { inlineMarkdown(text, style, onLink) }, modifier, color = color, style = body)
        return
    }
    val blocks = remember(text) { parseMarkdown(text) }
    Column(modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        for (block in blocks) {
            when (block) {
                is MdBlock.Paragraph -> Text(inlineMarkdown(block.text, style, onLink), color = color, style = body)
                is MdBlock.Heading -> Text(
                    inlineMarkdown(block.text, style, onLink),
                    color = color,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = when (block.level) { 1 -> 22.sp; 2 -> 19.sp; 3 -> 17.sp; else -> 16.sp },
                    modifier = Modifier.padding(top = 4.dp),
                )
                is MdBlock.Item -> Row(Modifier.padding(start = (block.depth * 16).dp)) {
                    Text(block.marker, Modifier.width(24.dp), color = atomic.textSecondary, style = body)
                    Text(inlineMarkdown(block.text, style, onLink), Modifier.weight(1f), color = color, style = body)
                }
                is MdBlock.Quote -> Row(Modifier.height(IntrinsicSize.Min)) {
                    Box(Modifier.width(3.dp).fillMaxHeight().background(atomic.bg2))
                    Text(
                        inlineMarkdown(block.text, style, onLink),
                        Modifier.padding(start = 10.dp),
                        color = atomic.textSecondary,
                        style = body,
                    )
                }
                MdBlock.Rule -> Box(Modifier.fillMaxWidth().height(1.dp).background(atomic.border))
                is MdBlock.Code -> CodeBlock(block)
                is MdBlock.Table -> TableBlock(block, style, color, onLink)
            }
        }
    }
}

@Composable
private fun CodeBlock(block: MdBlock.Code) {
    val atomic = MaterialTheme.atomic
    val clipboard = LocalClipboardManager.current
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(atomic.border)) {
        Row(Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp, top = 4.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Text(block.lang, Modifier.weight(1f), color = atomic.textSecondary, fontSize = 12.sp)
            Text(
                "Copy",
                Modifier.clickable { clipboard.setText(AnnotatedString(block.text)) }.padding(horizontal = 8.dp, vertical = 6.dp),
                color = atomic.main,
                fontSize = 12.sp,
            )
        }
        Text(
            block.text,
            Modifier.horizontalScroll(rememberScrollState()).padding(start = 12.dp, end = 12.dp, bottom = 10.dp),
            color = atomic.textPrimary,
            fontFamily = FontFamily.Monospace,
            fontSize = 13.sp,
        )
    }
}

@Composable
private fun TableBlock(table: MdBlock.Table, style: MdStyle, color: Color, onLink: (String) -> Unit) {
    val atomic = MaterialTheme.atomic
    Column(Modifier.horizontalScroll(rememberScrollState()).border(1.dp, atomic.border, RoundedCornerShape(6.dp))) {
        (listOf(table.header) + table.rows).forEachIndexed { r, row ->
            Row(Modifier.then(if (r == 0) Modifier.background(atomic.bg1) else Modifier)) {
                for (cell in row) {
                    Text(
                        inlineMarkdown(cell, style, onLink),
                        Modifier.width(120.dp).padding(8.dp),
                        color = color,
                        fontWeight = if (r == 0) FontWeight.SemiBold else FontWeight.Normal,
                        fontSize = 14.sp,
                    )
                }
            }
        }
    }
}
