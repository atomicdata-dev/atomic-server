package place.atomic.app.kotlin.chat

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.LinkAnnotation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import place.atomic.app.kotlin.ui.MdBlock
import place.atomic.app.kotlin.ui.MdStyle
import place.atomic.app.kotlin.ui.inlineMarkdown
import place.atomic.app.kotlin.ui.parseMarkdown

class MarkdownTest {
    @Test
    fun blocksAreParsedInOrder() {
        val blocks = parseMarkdown("# Title\n\nSome text\nover two lines.\n\n- one\n- two\n\n```kotlin\nval x = 1\n```\n\n> quoted\n\n| a | b |\n|---|---|\n| 1 | 2 |")
        assertEquals(MdBlock.Heading(1, "Title"), blocks[0])
        assertEquals(MdBlock.Paragraph("Some text over two lines."), blocks[1])
        assertTrue(blocks[2] is MdBlock.Item && blocks[3] is MdBlock.Item)
        assertEquals(MdBlock.Code("kotlin", "val x = 1"), blocks[4])
        assertEquals(MdBlock.Quote("quoted"), blocks[5])
        assertEquals(MdBlock.Table(listOf("a", "b"), listOf(listOf("1", "2"))), blocks[6])
    }

    @Test
    fun anUnclosedCodeFenceIsStillCode() {
        val blocks = parseMarkdown("```\nstreaming")
        assertEquals(MdBlock.Code("", "streaming"), blocks.single())
    }

    @Test
    fun inlineMarkupBecomesStylesAndLinks() {
        val opened = mutableListOf<String>()
        val text = inlineMarkdown("a **bold** and `code` and [Trip](did:ad:trip)", MdStyle(Color.Blue, Color.Gray)) { opened += it }
        assertEquals("a bold and code and Trip", text.text)
        val link = text.getLinkAnnotations(0, text.length).single()
        assertEquals(text.text.indexOf("Trip"), link.start)
        assertTrue(link.item is LinkAnnotation.Clickable)
    }
}
