import 'dart:async';
import 'dart:convert';

import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'embed_server.dart';
import 'native_views.dart';
import 'warm_resource_web_view.dart';

/// A resource as the web app draws it, without the web app around it: the
/// bundled renderer (`assets/embed`) in a web view, reading from this device's
/// store through a JavaScript channel. No server, no sign-in, no second copy of
/// the data in the page.
class ResourceView extends StatefulWidget {
  final AssistantApi api;
  final String drive;
  final String subject;
  final String title;

  /// A route of the web app to show instead of a resource (`/app/settings`).
  /// Then [subject] may be empty.
  final String? path;

  /// Where the bundled page comes from. A test swaps it for one that fails
  /// fast instead of starting a real server.
  static Future<EmbedServer> Function() serverFactory = EmbedServer.instance;

  /// The page itself. A test swaps in a fake that needs no web view: it gets
  /// the function the page's messages go to.
  @visibleForTesting
  static EmbedPage Function(void Function(String message) onMessage)?
      pageFactory;

  /// How long leaving waits for the page to hand over its last edits.
  @visibleForTesting
  static Duration flushTimeout = const Duration(seconds: 2);

  /// How long a closed page is kept (answering the store's last calls)
  /// before its web view is released.
  @visibleForTesting
  static Duration releaseDelay = const Duration(seconds: 3);

  /// Answers one call of the page. Replaceable in a test.
  final Future<String> Function(String method, String argsJson)? call;

  const ResourceView({
    super.key,
    required this.api,
    required this.drive,
    this.subject = '',
    this.title = '',
    this.path,
    this.call,
  });

  @override
  State<ResourceView> createState() => _ResourceViewState();
}

const _readMethods = {
  'getResource',
  'getResourcesWithSnapshots',
  'getLoroSnapshot',
  'query',
  'search',
  'allSubjects',
  'getDriveSubjects',
  'getVersionVectorsForDrive',
  'getVersionVectorsForSubjects',
  'getAllVersionVectors',
  'historyAttribution',
  'getBlob',
  'init',
  'agent',
};

/// What the screen needs of the page: run a script in it, and show it.
abstract class EmbedPage {
  Future<void> runJavaScript(String script);
  Future<Object> runJavaScriptReturningResult(String script);
  Widget build();
}

class _ResourceViewState extends State<ResourceView>
    with WidgetsBindingObserver {
  EmbedPage? _page;
  Object? _error;
  final _clock = Stopwatch()..start();
  bool _firstRead = true;
  ShellController? _shell;
  Route<dynamic>? _route;
  bool _leaving = false;
  bool _wasCurrent = true;
  int _flushes = 0;
  final _flushed = <int, Completer<void>>{};

  /// Pages that were closed while handing over their last edits: kept here
  /// (and answered) until they are done, so a close never cuts an edit off.
  static final _closing = <EmbedPage>{};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _start();
    // The route is known once this is in the tree.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _registerMenu();
    });
  }

  Future<void> _start() async {
    // A page loaded ahead by the shell, when there is one: no page load.
    final pool = ShellScope.maybeOf(context)?.warm;
    if (pool != null && widget.path == null && widget.subject.isNotEmpty) {
      final warm = pool.take();
      if (warm != null) {
        _attach(warm, warm: true);
        return;
      }
    }
    final fake = ResourceView.pageFactory;
    if (fake != null) {
      _page = fake(_onMessage);
      return;
    }
    try {
      final server = await ResourceView.serverFactory();
      final page = await WebViewEmbedPage.create(
        server.page.replace(queryParameters: {
          if (widget.path != null)
            'path': widget.path!
          else
            'subject': widget.subject,
        }),
        onMessage: _onMessage,
        onLoaded: _pageLoaded,
      );
      if (mounted) {
        setState(() => _page = page);
      } else {
        page.release();
      }
    } catch (e) {
      if (mounted) setState(() => _error = e);
    }
  }

  /// Takes a loaded [page] over: its messages come here, it is told the
  /// colour scheme and which resource to show. Everything a view does with
  /// its page is set up here, not when the page is made.
  void _attach(WarmPage page, {required bool warm}) {
    _warm = warm;
    _page = page;
    page.onMessage = _onMessage;
    page.onLoaded = _pageLoaded;
    if (warm) {
      debugPrint('[warm] taken ready=${page is WebViewEmbedPage ? page.age : 0}'
          ' ms after it started loading');
      final subject = jsonEncode(widget.subject);
      // `open` replaces the page's blank first entry, so back leaves the
      // resource; an older bundle only has `show`.
      unawaited(page.runJavaScript(
          'window.atomicEmbed&&(window.atomicEmbed.open||window.atomicEmbed.show)($subject)'));
    }
  }

  bool _warm = false;

  void _pageLoaded() {
    debugPrint('[embed] page loaded after ${_clock.elapsedMilliseconds} ms');
    // The page follows the app's light/dark mode for its own 'auto'.
    _scheme = null;
    if (mounted) _tellColorScheme();
  }

  /// The bar's last button becomes this resource's "more" menu (the web app's
  /// navbar menu, drawn by the page) while this page is the one on top. A
  /// `path` page (settings) has no resource and no menu.
  void _registerMenu() {
    final route = ModalRoute.of(context);
    if (route == null) return;
    _route = route;
    // A swipe back slides the page out, then waits for its last edits.
    if (route is SlideBackRoute) route.beforeSwipeLeave = _flushLeaving;
    if (widget.path != null) return;
    final shell = ShellScope.maybeOf(context);
    if (shell == null) return;
    _shell = shell;
    // Until the page has loaded there is nothing to open: the tap does
    // nothing.
    shell.registerMenu(
        route, () => _page?.runJavaScript('window.atomicEmbed?.openMenu()'));
  }

  /// The app's light/dark mode as the page last heard it.
  String? _scheme;

  void _tellColorScheme() {
    final scheme =
        Theme.of(context).brightness == Brightness.dark ? 'dark' : 'light';
    if (scheme == _scheme || _page == null) return;
    _scheme = scheme;
    unawaited(_page!
        .runJavaScript("window.atomicEmbed?.setColorScheme?.('$scheme')"));
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _tellColorScheme();
    // Another page was opened over this one (search, a linked resource):
    // this one may never be shown again, so its edits go now.
    final current = ModalRoute.of(context)?.isCurrent ?? true;
    if (_wasCurrent && !current && !_leaving) unawaited(_flush());
    _wasCurrent = current;
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // The app going to the background may be the last the page gets to run.
    if (state == AppLifecycleState.hidden ||
        state == AppLifecycleState.paused) {
      unawaited(_flush());
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    final route = _route;
    if (route != null) _shell?.unregisterMenu(route);
    if (route is SlideBackRoute && route.beforeSwipeLeave == _flushLeaving) {
      route.beforeSwipeLeave = null;
    }
    // Closed without going through [_leave] (the route was removed from
    // under it): hand over what is left, keeping the page until it has.
    final page = _page;
    if (!_leaving && page != null) {
      _closing.add(page);
      unawaited(_flush(leaving: true).whenComplete(() {
        _closing.remove(page);
        _release(page);
      }));
    } else if (page != null) {
      _release(page);
    }
    super.dispose();
  }

  /// Drops the web view a little later: the store may still be answering the
  /// page's last calls.
  void _release(EmbedPage page) {
    final releasable = page is ReleasablePage ? page as ReleasablePage : null;
    if (releasable == null) return;
    Future<void>.delayed(ResourceView.releaseDelay, releasable.release);
  }

  /// Asks the page to hand every pending edit to the store
  /// (`window.atomicEmbed.flush`), and waits for its answer: a `flushed`
  /// message, as `runJavaScript` does not wait for a promise. Gives up after
  /// [ResourceView.flushTimeout], so leaving never hangs on the page.
  Future<void> _flush({bool leaving = false}) {
    final page = _page;
    if (page == null) return Future.value();
    final id = ++_flushes;
    final done = Completer<void>();
    _flushed[id] = done;
    final reply = "AtomicFlutter.postMessage(JSON.stringify("
        "{method:'flushed',flush:$id}))";
    page
        .runJavaScript('Promise.resolve(window.atomicEmbed && '
            'window.atomicEmbed.flush && window.atomicEmbed.flush($leaving))'
            '.catch(function(){}).then(function(){$reply})')
        .catchError((_) {
      if (!done.isCompleted) done.complete();
    });
    return done.future.timeout(ResourceView.flushTimeout, onTimeout: () {
      debugPrint('[embed] flush $id: no answer, leaving anyway');
    }).whenComplete(() => _flushed.remove(id));
  }

  Future<void> _flushLeaving() {
    _leaving = true;
    return _flush(leaving: true);
  }

  /// A call from the page: `{id, method, args}`. Answered with
  /// `window.__atomicReply(id, ok, payload)`. A `flushed` message answers a
  /// [_flush].
  Future<void> _onMessage(String message) async {
    final request = jsonDecode(message) as Map<String, dynamic>;
    if (request['method'] == 'flushed') {
      final done = _flushed[request['flush']];
      if (done != null && !done.isCompleted) done.complete();
      return;
    }
    final id = request['id'] as int;
    final method = request['method'] as String;
    if (method == 'openNative') {
      await _answerOpenNative(id, request['args']);
      return;
    }
    final started = _clock.elapsedMilliseconds;
    String reply;
    // Writes show up in logcat, so what the page persists can be followed.
    if (kDebugMode && !_readMethods.contains(method)) {
      debugPrint('[embed] call $method (${message.length} chars)');
    }
    try {
      final answer = await (widget.call ?? widget.api.embedCall)(
          method, jsonEncode(request['args'] ?? const []));
      reply = 'true,${jsonEncode(answer)}';
      if (_firstRead && method == 'getResourcesWithSnapshots') {
        _firstRead = false;
        debugPrint('[embed] first read at $started ms, answered in '
            '${_clock.elapsedMilliseconds - started} ms');
        debugPrint(_warm
            ? '[warm] open ${_clock.elapsedMilliseconds} ms first content'
            : '[warm] cold open ${_clock.elapsedMilliseconds} ms first content');
      }
    } catch (e) {
      reply = 'false,${jsonEncode('$e')}';
    }
    // Answered after this screen is gone too: a page that is closing still
    // waits on the store (signing, applying its last commit).
    try {
      await _page?.runJavaScript('window.__atomicReply($id,$reply)');
    } catch (e) {
      debugPrint('[embed] reply to $method not delivered: $e');
    }
  }

  /// The page asks to show a resource in the app's own screen
  /// (`openNative(kind, subject, title)`): opened when the app has a native
  /// view for that kind, and the answer says whether it did, so the page draws
  /// the resource itself when not.
  Future<void> _answerOpenNative(int id, Object? args) async {
    var handled = false;
    if (args is List && args.length >= 2) {
      final kind = '${args[0]}';
      final subject = '${args[1]}';
      final title = args.length > 2 ? '${args[2]}' : '';
      if (mounted && subject.isNotEmpty && hasNativeView(kind)) {
        handled = true;
        widget.api.noteOpened(widget.drive, subject);
        unawaited(Navigator.of(context).push(SlideBackRoute<void>(
          builder: (_) => openResourceView(
              api: widget.api,
              drive: widget.drive,
              subject: subject,
              title: title,
              className: kind),
        )));
      }
    }
    try {
      await _page?.runJavaScript('window.__atomicReply($id,true,'
          '${jsonEncode(jsonEncode(handled))})');
    } catch (e) {
      debugPrint('[embed] reply to openNative not delivered: $e');
    }
  }

  /// Back goes one page back inside the page first (after an action opened
  /// its form, say), and leaves the resource when there is none.
  Future<void> _back() async {
    if (_leaving) return;
    final page = _page;
    if (page != null) {
      final went = await page
          .runJavaScriptReturningResult('window.atomicEmbed?.back() === true');
      if ('$went' == 'true' || went == true) return;
    }
    await _leave();
  }

  /// Leaves the resource once the page has handed over its last edits.
  Future<void> _leave() async {
    if (_leaving) return;
    _leaving = true;
    await _flush(leaving: true);
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final page = _page;
    return PopScope(
        canPop: false,
        onPopInvokedWithResult: (didPop, _) {
          if (!didPop) _back();
        },
        child: Scaffold(
          backgroundColor: c.bgBody,
          body: SafeArea(
            bottom: false,
            child: _error != null
                ? Center(
                    child: Text('$_error', style: TextStyle(color: c.alert)))
                : page == null
                    ? const Center(child: CircularProgressIndicator())
                    : Stack(children: [
                        // Swipe back starts at the left edge.
                        page.build(),
                        const Positioned(
                          left: 0,
                          top: 0,
                          bottom: 0,
                          width: 24,
                          child: _EdgeStrip(),
                        ),
                      ]),
          ),
        ));
  }
}

/// Catches touches at the screen's left edge so the swipe back works over the
/// page.
class _EdgeStrip extends StatelessWidget {
  const _EdgeStrip();

  @override
  Widget build(BuildContext context) => const Listener(
      behavior: HitTestBehavior.opaque, child: SizedBox.expand());
}
