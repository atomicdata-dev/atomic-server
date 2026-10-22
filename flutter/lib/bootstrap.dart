import 'package:flutter/material.dart';
import 'package:atomic_flutter/atomic_flutter.dart' show withCalmInteraction;

import 'screens/startup_failed_screen.dart';
import 'screens/store_recovery_screen.dart';

/// Everything `main` does before the app draws, behind seams so a test can
/// fail any step. Whatever fails, the window shows something: an error that
/// escaped `main` left it black for good.
Future<void> bootstrap({
  /// Loads the native library (`RustLib.init`).
  required Future<void> Function() initRust,

  /// Work that runs while the store opens (the saved theme).
  required Future<void> Function() ready,
  required Future<String> Function() documentsPath,

  /// Opens the store; the error as text, or null once it is open.
  required Future<String?> Function(String path) openDb,

  /// Runs once the store is open: system chrome, pickers, then `runApp`.
  required void Function() startApp,
  void Function(Widget app)? show,
  void Function(String step)? mark,
}) async {
  final run = show ?? runApp;
  var rustLoaded = false;

  /// A startup error as text, or null once the app runs. A store that does
  /// not open has its own screen; anything else lands in the general one.
  Future<String?> attempt() async {
    String? storeError;
    String? path;
    try {
      // The library only loads once: `RustLib.init` refuses a second call.
      if (!rustLoaded) {
        await initRust();
        rustLoaded = true;
      }
      mark?.call('rust init');
      path = await documentsPath();
      mark?.call('documents dir');
      storeError = await openDb(path);
      mark?.call('db open');
      await ready();
    } catch (e, st) {
      debugPrint('Starting the app failed: $e\n$st');
      return '$e\n\n$st';
    }
    if (storeError != null) {
      final dir = path;
      run(_fallbackApp(StoreOpenFailedScreen(
        error: storeError,
        onRetry: () async {
          final error = await openDb(dir);
          if (error == null) startApp();
          return error;
        },
      )));
      return null;
    }
    startApp();
    return null;
  }

  final first = await attempt();
  if (first != null) {
    run(_fallbackApp(StartupFailedScreen(
      error: first,
      onRetry: attempt,
    )));
  }
}

/// Light or dark by the system, nothing app specific.
Widget _fallbackApp(Widget home) => MaterialApp(
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.system,
      theme: withCalmInteraction(
        ThemeData(
          colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1976D2)),
          useMaterial3: true,
        ),
        ink: Colors.black,
      ),
      darkTheme: withCalmInteraction(
        ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFF1976D2),
            brightness: Brightness.dark,
          ),
          useMaterial3: true,
        ),
        ink: Colors.white,
      ),
      home: home,
    );
