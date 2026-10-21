import 'dart:io';

/// Where the local store lives.
///
/// Phones and tablets keep it in the app's documents directory, exactly as
/// before: moving it would orphan every existing install's data. On desktop the
/// documents directory is the user's own `~/Documents`, which macOS guards (TCC):
/// a freshly signed app has no permission there and the store cannot even be
/// created (EPERM). Desktop therefore uses the app-support directory, and copies
/// a store left in the old place across once.
Future<String> resolveStoreDirectory({
  required bool desktop,
  required Future<String> Function() documents,
  required Future<String> Function() support,
}) async {
  if (!desktop) return documents();
  final dir = await support();
  try {
    await Directory(dir).create(recursive: true);
    await _migrateLegacy(dir, await documents());
  } catch (_) {
    // Best effort: a missing legacy store or a denied read is not an error.
  }
  return dir;
}

/// Copies `atomic*` files and the `uploads` directory from [legacy] when [dir]
/// has no store yet. Never deletes or modifies anything in [legacy].
Future<void> _migrateLegacy(String dir, String legacy) async {
  if (File('$dir/atomic.redb').existsSync()) return;
  final old = File('$legacy/atomic.redb');
  if (!old.existsSync()) return;
  try {
    // The store first and under a temporary name, so an interrupted copy
    // never looks like a store.
    await old.copy('$dir/atomic.redb.migrating');
    for (final entity in Directory(legacy).listSync(followLinks: false)) {
      final name = entity.uri.pathSegments.where((s) => s.isNotEmpty).last;
      if (entity is File &&
          name.startsWith('atomic') &&
          !name.endsWith('.redb') &&
          !name.contains('.corrupt-')) {
        await entity.copy('$dir/$name');
      } else if (entity is Directory && name == 'uploads') {
        await _copyDir(entity, Directory('$dir/uploads'));
      }
    }
    await File('$dir/atomic.redb.migrating').rename('$dir/atomic.redb');
  } catch (_) {
    try {
      File('$dir/atomic.redb.migrating').deleteSync();
    } catch (_) {}
  }
}

Future<void> _copyDir(Directory from, Directory to) async {
  await to.create(recursive: true);
  for (final e in from.listSync(followLinks: false)) {
    final name = e.uri.pathSegments.where((s) => s.isNotEmpty).last;
    if (e is File) {
      await e.copy('${to.path}/$name');
    } else if (e is Directory) {
      await _copyDir(e, Directory('${to.path}/$name'));
    }
  }
}

/// Whether this platform stores its data in the app-support directory.
bool get storeInSupportDirectory =>
    Platform.isMacOS || Platform.isLinux || Platform.isWindows;
