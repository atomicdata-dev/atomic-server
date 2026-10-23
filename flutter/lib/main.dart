import 'dart:async';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:atomic_store_flutter/bridge/frb_generated.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart'
    show nativeLibrary;
import 'package:atomic_chat/atomic_chat.dart'
    show
        AppShell,
        BackgroundActivity,
        AppSidebarIcons,
        AppThemeMode,
        ChatsScreen,
        ToastController,
        ToastHost,
        defaultAttachmentPicker;
import 'assistant/atomic_assistant_api.dart';
import 'assistant/file_attachment_picker.dart';
import 'bootstrap.dart';
import 'perf_seed.dart';
import 'screens/login_screen.dart';
import 'screens/pair_screen.dart';
import 'screens/store_recovery_screen.dart';
import 'screens/sync_screen.dart';
import 'package:share_plus/share_plus.dart';
import 'package:atomic_flutter/atomic_flutter.dart'
    show AppScrollBehavior, Perf, withCalmInteraction;
import 'theme.dart';
import 'atomic/atomic_client.dart';
import 'atomic/session.dart';
import 'atomic/store_location.dart';
import 'atomic/sync_notice_policy.dart';

void main() async {
  Perf.start();
  WidgetsFlutterBinding.ensureInitialized();
  Perf.watchFrames();
  Perf.watchTaps();
  // Independent of the database, so read while it opens.
  final theme = Future.wait([AppThemeMode.load(), AppSidebarIcons.load()]);
  await bootstrap(
    initRust: () => RustLib.init(externalLibrary: nativeLibrary()),
    ready: () => theme,
    documentsPath: () => resolveStoreDirectory(
      desktop: storeInSupportDirectory,
      documents: () async => (await getApplicationDocumentsDirectory()).path,
      support: () async => (await getApplicationSupportDirectory()).path,
    ),
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
  Timer? _storeTick;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    BackgroundActivity.instance.hostPoller = AtomicClient.backgroundActivity;
    // Messages other people send arrive over the sync session at any time,
    // with no screen change to read them on: the conversations list and an
    // open conversation read the store again every so often (and when a
    // background sync finishes).
    _storeTick = Timer.periodic(const Duration(seconds: 20), (_) {
      if (_loggedIn) AtomicClient.notifyStoreChanged();
    });
    // The theme chosen on the settings page (the embedded web page).
    AppThemeMode.mode.addListener(_themeChanged);
    SharedPreferences.getInstance().then((p) {
      final ms = p.getInt(SyncNoticePolicy.prefsKey);
      if (ms != null) {
        _syncNotice.lastShown = DateTime.fromMillisecondsSinceEpoch(ms);
      }
    }, onError: (Object e) => debugPrint('Reading the notice time failed: $e'));
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
    _storeTick?.cancel();
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
    _inForeground = state == AppLifecycleState.resumed;
    // No requests to the device directory in the background. `inactive` is a
    // window that lost focus (desktop) or a passing interruption: not a
    // reason to stop looking for devices.
    if (state == AppLifecycleState.resumed) {
      AtomicClient.setAppForeground(true);
    } else if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden ||
        state == AppLifecycleState.detached) {
      AtomicClient.setAppForeground(false);
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

  /// Background sync retries on its own and is nearly always silent: a cold
  /// radio or a sleeping device fails once and works on the retry. Only a long
  /// stretch without reaching any device earns one calm notice (see
  /// [SyncNoticePolicy]); the details live on the Sync page.
  static const _syncToastKey = 'sync:error';
  late final _syncNotice = SyncNoticePolicy(
    onShown: (at) => SharedPreferences.getInstance().then(
      (p) => p.setInt(SyncNoticePolicy.prefsKey, at.millisecondsSinceEpoch),
      onError: (Object e) => debugPrint('Saving the notice time failed: $e'),
    ),
  );
  bool _inForeground = true;

  void _syncFailed(String message) {
    _syncFailures++;
    // The raw detail is for developers; the Sync page has the status.
    debugPrint('Background sync failed ($_syncFailures in a row): $message');
    if (_syncNotice.failed(inForeground: _inForeground)) {
      _toasts.show(
        _syncToastKey,
        "Couldn't sync right now. We'll keep trying.",
        icon: Icons.sync,
      );
    }
    _scheduleSyncRetry();
  }

  void _syncSucceeded() {
    _syncFailures = 0;
    _syncNotice.succeeded();
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
      // In the background nothing asks the device directory; coming back
      // starts a sync (see didChangeAppLifecycleState).
      if (mounted && _loggedIn && _inForeground) _startBackgroundSync();
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
        // What it imported (and what the open sync session brought meanwhile)
        // is in the store: lists and open conversations read it again.
        AtomicClient.notifyStoreChanged();
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
    _syncNotice.reset();
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
      scrollBehavior: const AppScrollBehavior(),
      navigatorKey: _navKey,
      builder: (context, child) =>
          ToastHost(controller: _toasts, child: child ?? const SizedBox()),
      title: 'atomic.place',
      debugShowCheckedModeBanner: false,
      themeMode: themeMode,
      theme: withCalmInteraction(
        ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFF1976D2),
            brightness: Brightness.light,
          ),
          useMaterial3: true,
          brightness: Brightness.light,
          scaffoldBackgroundColor: AppColors.light.pageBg,
          extensions: const [AppColors.light],
        ),
        // A flat wash of the text colour on press, no expanding ink.
        ink: AppColors.light.textPrimary,
      ),
      darkTheme: withCalmInteraction(
        ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFF1976D2),
            brightness: Brightness.dark,
          ),
          useMaterial3: true,
          brightness: Brightness.dark,
          scaffoldBackgroundColor: AppColors.dark.pageBg,
          extensions: const [AppColors.dark],
        ),
        ink: AppColors.dark.textPrimary,
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
