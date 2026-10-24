package place.atomic.app.kotlin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import place.atomic.app.kotlin.ui.decodeQr
import place.atomic.app.kotlin.ui.lumaOf
import place.atomic.app.kotlin.ui.qrBitmap

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class QrTest {
    @Test
    fun the_code_this_device_shows_is_read_back_by_the_scanner() {
        val text = "atomic:node:${"ab".repeat(32)}:Joep%27s%20phone"
        val bitmap = qrBitmap(text, 400)
        assertEquals(text, decodeQr(lumaOf(bitmap), bitmap.width, bitmap.height))
    }

    @Test
    fun a_camera_row_stride_wider_than_the_image_is_handled() {
        val text = "atomic:node:${"cd".repeat(32)}"
        val bitmap = qrBitmap(text, 300)
        val luma = lumaOf(bitmap)
        val stride = bitmap.width + 20
        val padded = ByteArray(stride * bitmap.height)
        for (y in 0 until bitmap.height) System.arraycopy(luma, y * bitmap.width, padded, y * stride, bitmap.width)
        assertEquals(text, decodeQr(padded, bitmap.width, bitmap.height, stride))
    }

    @Test
    fun a_frame_without_a_code_is_nothing() {
        assertNull(decodeQr(ByteArray(200 * 200) { 127 }, 200, 200))
    }
}
