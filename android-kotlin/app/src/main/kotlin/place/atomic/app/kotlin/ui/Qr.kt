package place.atomic.app.kotlin.ui

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** A QR code for `text` as a black on white bitmap, `size` pixels square with a quiet zone. */
fun qrBitmap(text: String, size: Int = 512): Bitmap {
    val hints = mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 1)
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
    val pixels = IntArray(size * size) { i -> if (matrix.get(i % size, i / size)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
    return Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
}

/**
 * The text of a QR code in a frame of 8-bit luminance (the Y plane of a camera
 * image), `rowStride` bytes per row; `null` when there is none in the frame.
 */
fun decodeQr(luma: ByteArray, width: Int, height: Int, rowStride: Int = width): String? {
    val packed = if (rowStride == width) luma else ByteArray(width * height).also { out ->
        for (y in 0 until height) System.arraycopy(luma, y * rowStride, out, y * width, width)
    }
    val source = PlanarYUVLuminanceSource(packed, width, height, 0, 0, width, height, false)
    return try {
        QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), mapOf(DecodeHintType.TRY_HARDER to true)).text
    } catch (_: NotFoundException) {
        null
    } catch (_: com.google.zxing.FormatException) {
        null
    } catch (_: com.google.zxing.ChecksumException) {
        null
    }
}

/** Luminance of a bitmap, for tests and for decoding a picture. */
fun lumaOf(bitmap: Bitmap): ByteArray = ByteArray(bitmap.width * bitmap.height) { i ->
    val c = bitmap.getPixel(i % bitmap.width, i / bitmap.width)
    (((c shr 16 and 0xFF) * 299 + (c shr 8 and 0xFF) * 587 + (c and 0xFF) * 114) / 1000).toByte()
}
