import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'src/rust/frb_generated.dart';
import 'package:atomic_chat/atomic_chat.dart'
    show AppShell, AppThemeMode, ChatsScreen, ToastController, ToastHost, ToastSeverity, defaultAttachmentPicker;
import 'assistant/atomic_assistant_api.dart';
import 'assistant/file_attachment_picker.dart';
import 'bootstrap.dart';
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
  Perf.watchTaps();
  // Independent of the database, so read while it opens.
  final theme = AppThemeMode.load();
  await bootstrap(
    initRust: RustLib.init,
    ready: () => theme,
    documentsPath: () async => (await getApplicationDocumentsDirectory()).path,
    openDb: _openDb,
    startApp: () {
      SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
      defaultAttachmentPicker = const FileSelectorAttachmentPicker();
      _runAtomicApp();
    },
    mark: Perf.mark,
  );
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

  /// Android says when the network changed (MainActivity): look for the
  /// other devices again at once instead of at the next backoff step.
  static const _networkChannel = MethodChannel('app.atomicdata.app/network');
  Timer? _eventPoller;
  bool _backgroundSyncRunning = false;
  final _toasts = ToastController();
  int _syncFailures = 0;
  Timer? _syncRetry;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // The theme chosen on the settings page (the embedded web page).
    AppThemeMode.mode.addListener(_themeChanged);
    _handleInitialLink();
    _linkChannel.setMethodCallHandler(_handleLinkCall);
    _networkChannel.setMethodCallHandler((call) async {
      if (call.method == 'changed') AtomicClient.peerSearchAgain();
    });
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
    _syncRetry?.cancel();
    _toasts.dispose();
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

  /// Background sync is quiet about a single failure: a cold radio or a
  /// device waking from sleep times out once and works on the retry. It
  /// retries on its own with growing waits and speaks (one small toast, which
  /// the controller keeps unique and quiet for a while after dismissal) only
  /// from the [_toastAfterFailures]th failure in a row.
  static const _toastAfterFailures = 2;
  static const _syncToastKey = 'sync:error';

  void _syncFailed(String message) {
    _syncFailures++;
    debugPrint('Background sync failed ($_syncFailures in a row): $message');
    if (_syncFailures >= _toastAfterFailures) {
      _toasts.show(
        _syncToastKey,
        message,
        severity: ToastSeverity.error,
        icon: Icons.sync_problem,
        actionLabel: 'Retry',
        onAction: () {
          _syncFailures = 0;
          _startBackgroundSync();
        },
      );
    }
    _scheduleSyncRetry();
  }

  void _syncSucceeded() {
    _syncFailures = 0;
    _syncRetry?.cancel();
    _toasts.resolve(_syncToastKey);
  }

  void _scheduleSyncRetry() {
    _syncRetry?.cancel();
    if (!_loggedIn) return;
    // 20 s, 40 s, 80 s … at most 5 min.
    final seconds =
        (20 * (1 << (_syncFailures - 1).clamp(0, 4))).clamp(20, 300);
    _syncRetry = Timer(Duration(seconds: seconds), () {
      if (mounted && _loggedIn) _startBackgroundSync();
    });
  }

  /// Auto-sync known peers / pkarr after login (no Settings → Retry needed).
  void _startBackgroundSync() {
    if (_backgroundSyncRunning) return;
    _backgroundSyncRunning = true;
    _syncRetry?.cancel();
    Future(() async {
      try {
        final report = await AtomicClient.syncConnectivityNow();
        if (!mounted) return;

        // Only a failure is worth a notice; being connected is the normal case.
        if (report.livePeers == 0 &&
            report.imported == 0 &&
            !report.message.startsWith('No other device found yet')) {
          _syncFailed(report.message);
        } else {
          _syncSucceeded();
        }
      } catch (e) {
        if (mounted) _syncFailed('Sync: $e');
      } finally {
        _backgroundSyncRunning = false;
      }
    });
  }

  void _signedOut() {
    _syncRetry?.cancel();
    _syncFailures = 0;
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
      builder: (context, child) =>
          ToastHost(controller: _toasts, child: child ?? const SizedBox()),
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
        // A press shows a faint wash of the text colour, as the embedded page
        // does, not the default tinted flat rectangle.
        splashColor: AppColors.light.textPrimary.withValues(alpha: 0.06),
        highlightColor: AppColors.light.textPrimary.withValues(alpha: 0.08),
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
        // A press shows a faint wash of the text colour, as the embedded page
        // does, not the default tinted flat rectangle.
        splashColor: AppColors.dark.textPrimary.withValues(alpha: 0.06),
        highlightColor: AppColors.dark.textPrimary.withValues(alpha: 0.08),
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
