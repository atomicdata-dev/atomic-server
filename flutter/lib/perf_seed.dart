import 'dart:io';

import 'package:atomic_flutter/atomic_flutter.dart' show Perf;
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import 'atomic/atomic_client.dart';

/// Test data for `scripts/perf_android.sh`, in debug and profile builds only
/// (compiled out of a release build).
///
/// The script writes a number to `perf_seed` in the app's external files
/// directory (`/sdcard/Android/data/<package>/files/perf_seed`, which adb can
/// write without root); after sign-in the app makes that many documents and
/// folders in the active drive, opens each once (so Recents fills) and adds
/// three AI chats, then deletes the file.
Future<void> perfSeedIfAsked() async {
  if (kReleaseMode || kIsWeb || !Platform.isAndroid) return;
  final File flag;
  final int count;
  try {
    final dir = await getExternalStorageDirectory();
    if (dir == null) return;
    flag = File('${dir.path}/perf_seed');
    if (!flag.existsSync()) return;
    count = int.tryParse(flag.readAsStringSync().trim()) ?? 30;
    flag.deleteSync();
  } catch (_) {
    return;
  }
  final drive = AtomicClient.getActiveDrive();
  if (drive == null) return;
  final watch = Stopwatch()..start();
  for (var i = 0; i < count; i++) {
    final folder = i % 3 == 2;
    final subject = await AtomicClient.createResourceOfClass(
      drive,
      folder
          ? 'https://atomicdata.dev/classes/Folder'
          : 'https://atomicdata.dev/classes/DocumentV2',
      folder ? 'Perf folder $i' : 'Perf document $i',
    );
    AtomicClient.noteResourceOpened(drive, subject);
  }
  for (var i = 0; i < 3; i++) {
    await AtomicClient.createAiChat('Perf chat $i');
  }
  Perf.span('perf seed $count', watch.elapsedMilliseconds);
}
