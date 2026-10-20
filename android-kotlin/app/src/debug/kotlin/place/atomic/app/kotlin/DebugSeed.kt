package place.atomic.app.kotlin

import android.content.Context
import place.atomic.app.kotlin.core.activeDrive
import place.atomic.app.kotlin.core.addFavorite
import place.atomic.app.kotlin.core.createAiChat
import place.atomic.app.kotlin.core.createDocument
import place.atomic.app.kotlin.core.createFolder
import place.atomic.app.kotlin.core.noteResourceOpened

/**
 * Test data for debug builds (compiled out of release, see the release source
 * set). Twin of `flutter/lib/perf_seed.dart`.
 *
 * Write a number to `perf_seed` in the app's external files directory
 * (`adb shell "echo 30 > /sdcard/Android/data/place.atomic.app.kotlin/files/perf_seed"`,
 * adb can write there without root); on the next start the app makes that many
 * documents and folders in the active drive, opens each once (so Recents
 * fills), adds three AI chats and favorites the first three, then deletes the file.
 */
object DebugSeed {
    suspend fun runIfAsked(context: Context) {
        val flag = context.getExternalFilesDir(null)?.resolve("perf_seed") ?: return
        if (!flag.exists()) return
        val count = flag.readText().trim().toIntOrNull() ?: 30
        flag.delete()
        val drive = activeDrive() ?: return
        val favorites = mutableListOf<String>()
        for (i in 0 until count) {
            val folder = i % 3 == 2
            val subject = if (folder) createFolder(drive, "Perf folder $i") else createDocument(drive, "Perf document $i")
            noteResourceOpened(drive, subject)
            if (favorites.size < 3) favorites += subject
        }
        repeat(3) { createAiChat("Perf chat $it") }
        favorites.forEach { addFavorite(it) }
    }
}
