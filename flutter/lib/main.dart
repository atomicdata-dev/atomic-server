import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'src/rust/frb_generated.dart';
import 'package:atomic_chat/atomic_chat.dart'
    show AppShell, AppThemeMode, ChatsScreen, defaultAttachmentPicker;
import 'assistant/atomic_assistant_api.dart';
import 'assistant/file_attachment_picker.dart';
import 'perf_seed.dart';
import 'screens/login_screen.dart';
import 'screens/pair_screen.dart';
import 'screens/store_recovery_screen.dart';
import 'screens/sync_screen.dart';
import 'package:share_plus/share_plus.dart';
import 'package:atomic_flutter/atomic_flutter.dart' show Perf;
import 'theme.dart';
import 'atomic/atomic_client.dart';
import 'atomic/session.dart';

void main() async {
  Perf.start();
  WidgetsFlutterBinding.ensureInitialized();
  Perf.watchFrames();
  // Independent of the database, so read while it opens.
  final theme = AppThemeMode.load();
  await RustLib.init();
  Perf.mark('rust init');
  final dir = await getApplicationDocumentsDirectory();
  Perf.mark('documents dir');
  // Whatever happens here, the app draws something: an error that escaped
  // `main` before `runApp` left it black for good.
  final openError = await _openDb(dir.path);
  Perf.mark('db open');
  SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  await theme;
  defaultAttachmentPicker = const FileSelectorAttachmentPicker();
  if (openError != null) {
    runApp(MaterialApp(
      debugShowCheckedModeBanner: false,
      home: StoreOpenFailedScreen(
        error: openError,
        onRetry: () async {
          final error = await _openDb(dir.path);
          if (error == null) _runAtomicApp();
          return error;
        },
      ),
    ));
    return;
  }
  _runAtomicApp();
}

/// Open the store; the error as text, or null once it is open.
Future<String?> _openDb(String path) async {
  try {
    await AtomicClient.openDb(path);
    return null;
  } catch (e) {
    debugPrint('Opening the local store failed: $e');
    return '$e';
  }
}

void _runAtomicApp() {
  Perf.mark('runApp');
  runApp(AtomicApp(storeRecovery: AtomicClient.storeRecovery()));
  // The saved session (secure storage: a few hundred ms the first time),
  // read once for the sign-in screen, which builds next. Not earlier: the
  // read competes with the first frame for the main thread.
  AtomicSession.preload();
  WidgetsBinding.instance.waitUntilFirstFrameRasterized
      .then((_) => Perf.mark('first frame'));
}

Future<void> _shareDamagedStore(String path) async {
  await SharePlus.instance.share(ShareParams(
    files: [XFile(path, mimeType: 'application/octet-stream')],
    subject: 'Damaged atomic.place store',
    text: 'The local store the app could not open.',
  ));
}

class AtomicApp extends StatefulWidget {
  const AtomicApp({super.key, this.storeRecovery});

  /// Set when the local store was damaged and replaced at this start: the
  /// app says so before anything else.
  final StoreRecoveryNotice? storeRecovery;

  @override
  State<AtomicApp> createState() => _AtomicAppState();
}

class _AtomicAppState extends State<AtomicApp> with WidgetsBindingObserver {
  bool _loggedIn = false;
  late StoreRecoveryNotice? _storeRecovery = widget.storeRecovery;
  final _navKey = GlobalKey<NavigatorState>();
  static const _linkChannel = MethodChannel('app.atomicdata.app/deeplink');
  Timer? _eventPoller;
  bool _backgroundSyncRunning = false;
  final Map<String, DateTime> _lastSyncSnackAt = {};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // The theme chosen on the settings page (the embedded web page).
    AppThemeMode.mode.addListener(_themeChanged);
    _handleInitialLink();
    _linkChannel.setMethodCallHandler(_handleLinkCall);
    // A cold start resumes in the sign-in screen (`_tryAutoLogin`); this one
    // is for coming back from the background.
  }

  /// Same path as LoginScreen auto-login: session → WS → Iroh discover fallback.
  Future<void> _resumeFromSession() async {
    final session = await AtomicSession.load();
    if (session == null || session.secret.isEmpty) return;

    try {
      final status = await AtomicClient.resumeSession(
        serverUrl: session.serverUrl,
        secret: session.secret,
        drive: session.drive,
      );
      final drive = AtomicClient.getActiveDrive();
      if (drive != null) {
        await AtomicSession.saveDrive(drive);
      }
      if (status == 'ok' && mounted) {
        _onLoggedIn();
      } else if (mounted) {
        // Still try Iroh when drive missing locally
        _startBackgroundSync();
      }
    } catch (e) {
      debugPrint('Session resume failed: $e');
    }
  }

  @override
  void dispose() {
    _eventPoller?.cancel();
    AppThemeMode.mode.removeListener(_themeChanged);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // In the background Android may kill the app without warning: make the
    // last writes durable now rather than at the next flush tick.
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden ||
        state == AppLifecycleState.detached) {
      AtomicClient.flushDb().catchError(
          (Object e) => debugPrint('Flushing the store failed: $e'));
    }
    if (state == AppLifecycleState.resumed && _loggedIn) {
      _resumeFromSession();
      _startBackgroundSync();
    }
  }

  bool _listening = false;

  void _startEventListener() {
    // One loop for the app's life (each resume signs in again).
    if (_listening) return;
    _listening = true;
    _eventPoller?.cancel();
    // Reactive loop: blocks in Rust until an event arrives
    Future(() async {
      while (mounted) {
        final event = await AtomicClient.waitForSyncEvent();
        if (event == null) continue;

        final kind = event['kind'] as String? ?? 'sync';
        if (kind == 'connected' || kind == 'disconnected') {
          AtomicClient.notifyLivePeersChanged();
        }
        // Syncing and connecting are silent: no toast for routine progress.
      }
    });
  }

  Future<void> _handleInitialLink() async {
    // Check if the app was launched from a did:ad:node: link
    try {
      final link = await _linkChannel.invokeMethod<String>('getInitialLink');
      if (link != null) _handleDeepLink(link);
    } catch (_) {}
  }

  Future<dynamic> _handleLinkCall(MethodCall call) async {
    if (call.method == 'onNewLink') {
      _handleDeepLink(call.arguments as String);
    }
  }

  void _handleDeepLink(String uri) {
    final peer = PairScreen.parsePeerInfo(uri);
    if (peer == null) return;
    final nodeId = peer.nodeId;
    // Show pair dialog once the app is ready
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final ctx = _navKey.currentContext;
      if (ctx != null) {
        PairScreen.show(ctx, nodeId: nodeId);
      }
    });
  }

  void _onLoggedIn() {
    Perf.once('session restored');
    setState(() => _loggedIn = true);
    unawaited(perfSeedIfAsked());
    _startEventListener();
    _startBackgroundSync();
  }

  void _showDebouncedSnack(BuildContext ctx, String key, String message,
      {Duration minInterval = const Duration(seconds: 15)}) {
    final now = DateTime.now();
    final last = _lastSyncSnackAt[key];
    if (last != null && now.difference(last) < minInterval) return;
    _lastSyncSnackAt[key] = now;
    ScaffoldMessenger.of(ctx).showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 2)),
    );
  }

  /// Auto-sync known peers / pkarr after login (no Settings → Retry needed).
  void _startBackgroundSync() {
    if (_backgroundSyncRunning) return;
    _backgroundSyncRunning = true;
    Future(() async {
      try {
        final report = await AtomicClient.syncConnectivityNow();
        if (!mounted) return;
        final ctx = _navKey.currentContext;
        if (ctx == null || !ctx.mounted) return;

        // Only a failure is worth a toast; being connected is the normal case.
        if (report.livePeers == 0 &&
            report.imported == 0 &&
            !report.message.contains('No peers online')) {
          _showDebouncedSnack(ctx, 'sync:error', report.message,
              minInterval: const Duration(seconds: 5));
        }
      } catch (e) {
        debugPrint('Background sync: $e');
        final ctx = _navKey.currentContext;
        if (ctx != null && ctx.mounted) {
          _showDebouncedSnack(ctx, 'sync:error', 'Sync: $e',
              minInterval: const Duration(seconds: 5));
        }
      } finally {
        _backgroundSyncRunning = false;
      }
    });
  }

  void _signedOut() {
    setState(() {
      _loggedIn = false;
    });
  }

  void _themeChanged() {
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final themeMode = AppThemeMode.mode.value;
    final isDark = switch (themeMode) {
      ThemeMode.dark => true,
      ThemeMode.light => false,
      ThemeMode.system =>
        View.of(context).platformDispatcher.platformBrightness ==
            Brightness.dark,
    };
    SystemChrome.setSystemUIOverlayStyle(SystemUiOverlayStyle(
      // The bottom bar's own surface behind the OS buttons, so they form one
      // block; Android must not tint it back to a scrim.
      systemNavigationBarColor:
          (isDark ? AppColors.dark : AppColors.light).barSurface,
      systemNavigationBarDividerColor: Colors.transparent,
      systemNavigationBarContrastEnforced: false,
      systemNavigationBarIconBrightness:
          isDark ? Brightness.light : Brightness.dark,
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
    ));
    return MaterialApp(
      navigatorKey: _navKey,
      title: 'atomic.place',
      debugShowCheckedModeBanner: false,
      themeMode: themeMode,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1976D2),
          brightness: Brightness.light,
        ),
        useMaterial3: true,
        brightness: Brightness.light,
        scaffoldBackgroundColor: AppColors.light.pageBg,
        extensions: const [AppColors.light],
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1976D2),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: AppColors.dark.pageBg,
        extensions: const [AppColors.dark],
      ),
      home: _storeRecovery != null
          ? StoreRecoveryScreen(
              notice: _storeRecovery!,
              onContinue: () => setState(() => _storeRecovery = null),
              onShare: _shareDamagedStore,
            )
          : !_loggedIn
              ? LoginScreen(onLoggedIn: _onLoggedIn)
              : AppShell(
                  api: const AtomicAssistantApi(),
                  drive: AtomicClient.getActiveDrive() ?? '',
                  profile: (_) => const SyncScreen(),
                  home: ChatsScreen(
                    api: const AtomicAssistantApi(),
                    drive: AtomicClient.getActiveDrive() ?? '',
                    onSignOut: _signedOut,
                  ),
                ),
    );
  }
}
