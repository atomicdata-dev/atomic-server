package place.atomic.app.kotlin

import android.view.ViewGroup
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import place.atomic.app.kotlin.embed.EmbedController
import place.atomic.app.kotlin.embed.EmbedCore

/**
 * The page lays itself out for the viewport it loads in, so the warm WebView
 * must not be 0 x 0 (the blank body on a Samsung Tab S9+) and must fill the
 * screen it is attached to.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w1317dp-h715dp-xhdpi")
class EmbedControllerTest {
    private val core = object : EmbedCore {
        override suspend fun dispatch(method: String, argsJson: String) = "null"
    }

    @Test
    fun the_warm_view_has_the_size_of_the_screen_before_it_is_shown() {
        val controller = EmbedController(ApplicationProvider.getApplicationContext(), CoroutineScope(Dispatchers.Unconfined), core)
        controller.warm()
        val view = controller.attach(ApplicationProvider.getApplicationContext())
        val metrics = ApplicationProvider.getApplicationContext<android.content.Context>().resources.displayMetrics
        assertEquals(metrics.widthPixels, view.measuredWidth)
        assertEquals(metrics.heightPixels, view.measuredHeight)
    }

    @Test
    fun an_attached_view_asks_its_parent_for_all_of_the_space() {
        val controller = EmbedController(ApplicationProvider.getApplicationContext(), CoroutineScope(Dispatchers.Unconfined), core)
        val view = controller.attach(ApplicationProvider.getApplicationContext())
        assertEquals(ViewGroup.LayoutParams.MATCH_PARENT, view.layoutParams.width)
        assertEquals(ViewGroup.LayoutParams.MATCH_PARENT, view.layoutParams.height)
    }
}
