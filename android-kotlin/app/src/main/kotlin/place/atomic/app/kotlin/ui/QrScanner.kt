package place.atomic.app.kotlin.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

/**
 * The camera, looking for a pairing code. CameraX gives frames; ZXing reads
 * them (no Google Play services needed). Asks for the camera permission when it
 * shows; without it, says how to get on without (paste the code). Not run on a
 * device by the author of this change.
 */
@Composable
fun QrScanner(onCode: (String) -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    if (!granted) {
        Column(modifier.padding(8.dp)) {
            Text("Allow the camera to scan the other device's code, or paste its node ID instead.")
            OutlinedButton({ ask.launch(Manifest.permission.CAMERA) }, Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Allow camera") }
        }
        return
    }

    val lifecycle = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val latest by androidx.compose.runtime.rememberUpdatedState(onCode)
    val preview = remember { PreviewView(context) }
    DisposableEffect(lifecycle) {
        val future = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        future.addListener({
            val bound = future.get()
            provider = bound
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(executor) { image ->
                try {
                    val plane = image.planes[0]
                    val bytes = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
                    decodeQr(bytes, image.width, image.height, plane.rowStride)?.let { text ->
                        preview.post { latest(text) }
                    }
                } finally {
                    image.close()
                }
            }
            val view = Preview.Builder().build().also { it.setSurfaceProvider(preview.surfaceProvider) }
            bound.unbindAll()
            bound.bindToLifecycle(lifecycle, CameraSelector.DEFAULT_BACK_CAMERA, view, analysis)
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            provider?.unbindAll()
            executor.shutdown()
        }
    }
    AndroidView({ preview }, modifier.fillMaxSize())
}
