import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'src/rust/frb_generated.dart';
import 'package:atomic_chat/atomic_chat.dart' show AppShell, ChatsScreen;
import 'assistant/atomic_assistant_api.dart';
import 'canvas/infinite_canvas.dart';
import 'gallery/canvas_store.dart';
import 'gallery/gallery_screen.dart';
import 'models/canvas_entry.dart';
import 'screens/login_screen.dart';
import 'screens/pair_screen.dart';
import 'screens/sync_screen.dart';
import 'theme.dart';
import 'atomic/atomic_client.dart';
import 'atomic/session.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  final dir = await getApplicationDocumentsDirectory();
  await AtomicClient.openDb(dir.path);
  SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  runApp(const AtomicCanvasApp());
}

class AtomicCanvasApp extends StatefulWidget {
  const AtomicCanvasApp({super.key});

  @override
  State<AtomicCanvasApp> createState() => _AtomicCanvasAppState();
}

class _AtomicCanvasAppState extends State<AtomicCanvasApp>
    with WidgetsBindingObserver {
  final CanvasStore _store = CanvasStore();
  CanvasEntry? _openCanvas;
  bool _loggedIn = false;
  bool _showGallery = false;
  final _navKey = GlobalKey<NavigatorState>();
  static const _linkChannel = MethodChannel('app.atomicdata.canvas/deeplink');
  Timer? _eventPoller;
  bool _backgroundSyncRunning = false;
  final Map<String, DateTime> _lastSyncSnackAt = {};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _handleInitialLink();
    _linkChannel.setMethodCallHandler(_handleLinkCall);
    _resumeFromSession();
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
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && _loggedIn) {
      _resumeFromSession();
      _startBackgroundSync();
    }
  }

  void _startEventListener() {
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
    _store.isDarkMode =
        View.of(context).platformDispatcher.platformBrightness ==
            Brightness.dark;
    setState(() => _loggedIn = true);
    _store.load().then((_) {
      if (mounted) setState(() {});
    });
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
      _showGallery = false;
      _openCanvas = null;
      _store.canvases.clear();
    });
  }

  void _openFromGallery(CanvasEntry canvas) async {
    final isDarkMode = View.of(context).platformDispatcher.platformBrightness ==
        Brightness.dark;
    await _store.loadStrokes(canvas, isDarkMode: isDarkMode);
    if (canvas.id.isNotEmpty) {
      AtomicClient.wsSubscribeCanvas(canvas.id).catchError((_) {});
    }
    if (mounted) setState(() => _openCanvas = canvas);
  }

  void _newCanvas({String? folderId}) {
    if (_openCanvas != null && _openCanvas!.strokes.isEmpty) {
      _store.deleteCanvases([_openCanvas!.id]);
    }
    final canvas = _store.createCanvas(folderId: folderId);
    setState(() => _openCanvas = canvas);
    if (canvas.id.isNotEmpty) {
      AtomicClient.wsSubscribeCanvas(canvas.id).catchError((_) {});
    }
  }

  void _closeCanvas() {
    if (_openCanvas != null) {
      final isDarkMode =
          View.of(context).platformDispatcher.platformBrightness ==
              Brightness.dark;
      _store.onCanvasChanged(_openCanvas!, _openCanvas!.strokes,
          isDarkMode: isDarkMode,
          penColor: _openCanvas!.penColor,
          prevColor: _openCanvas!.prevColor);
    }
    if (_openCanvas != null && _openCanvas!.strokes.isEmpty) {
      _store.deleteCanvases([_openCanvas!.id]);
    }
    setState(() => _openCanvas = null);
  }

  @override
  Widget build(BuildContext context) {
    final isDark = View.of(context).platformDispatcher.platformBrightness ==
        Brightness.dark;
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
      themeMode: ThemeMode.system,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1976D2),
          brightness: Brightness.light,
        ),
        useMaterial3: true,
        brightness: Brightness.light,
        scaffoldBackgroundColor: AppColors.light.canvasBg,
        extensions: const [AppColors.light],
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1976D2),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: AppColors.dark.canvasBg,
        extensions: const [AppColors.dark],
      ),
      home: !_loggedIn
          ? LoginScreen(onLoggedIn: _onLoggedIn)
          : _openCanvas == null && !_showGallery
              ? AppShell(
                  api: const AtomicAssistantApi(),
                  drive: AtomicClient.getActiveDrive() ?? '',
                  profile: (_) => const SyncScreen(),
                  home: ChatsScreen(
                    api: const AtomicAssistantApi(),
                    drive: AtomicClient.getActiveDrive() ?? '',
                    onOpenGallery: () => setState(() => _showGallery = true),
                    onSignOut: _signedOut,
                  ),
                )
              : !_store.isLoaded
                  ? Scaffold(
                      backgroundColor:
                          Theme.of(context).extension<AppColors>()?.canvasBg ??
                              AppColors.dark.canvasBg,
                      body: const SafeArea(
                          child: Center(child: CircularProgressIndicator())),
                    )
                  : _openCanvas != null
                      ? InfiniteCanvas(
                          key: ValueKey(_openCanvas!.id),
                          canvas: _openCanvas!,
                          store: _store,
                          onClose: _closeCanvas,
                          onNewCanvas: _newCanvas,
                        )
                      : GalleryScreen(
                          store: _store,
                          onOpen: _openFromGallery,
                          onNew: ({folderId}) => _newCanvas(folderId: folderId),
                          onExit: () => setState(() => _showGallery = false),
                          onSignOut: _signedOut,
                        ),
    );
  }
}
