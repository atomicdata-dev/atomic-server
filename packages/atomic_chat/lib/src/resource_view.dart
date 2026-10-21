import 'dart:async';
import 'dart:convert';

import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt, Perf;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'app_top_bar.dart';
import 'slide_back_route.dart';
import 'app_shell.dart';
import 'app_theme.dart';
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

  /// How long the page's placeholder ([ResourceSkeleton]) may stay at most
  /// when the page never says it shows the resource: a warm page that was
  /// told to open it, and a cold one from its start (it loads the bundle).
  @visibleForTesting
  static Duration revealWarm = const Duration(milliseconds: 2000);
  @visibleForTesting
  static Duration revealCold = const Duration(seconds: 8);

  /// The placeholder's fade when the page shows the resource.
  static const revealFade = Duration(milliseconds: 90);

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

  /// Whether the web view is shown. Until then a [ResourceSkeleton] in the
  /// page's colours covers it (the resource's title where the page's header
  /// will be), never a black box or a spinner: a page that was told to open
  /// a resource first shows the last one, or its own loading state.
  bool _revealed = true;

  /// The placeholder is gone (faded out).
  bool _skeletonGone = true;
  Timer? _revealCap;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // A resource page in a real web view starts covered; a page of the app's
    // own (settings) and a test's page do not.
    if (widget.path == null) {
      _revealed = false;
      _skeletonGone = false;
      _revealCap = Timer(ResourceView.revealCold, _reveal);
    }
    _start();
    // The route is known once this is in the tree.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _registerMenu();
    });
  }

  /// The shell's warm pool, which may hold a read started on the row's
  /// pointer-down ([WarmResourceWebView.prefetch]).
  WarmResourceWebView? _pool;

  Future<void> _start() async {
    // A page loaded ahead by the shell, when there is one: no page load.
    final pool = _pool = ShellScope.maybeOf(context)?.warm;
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
      // Only a page that can say it shows the resource is covered.
      if (_page is! WarmPage) {
        _revealCap?.cancel();
        _revealed = _skeletonGone = true;
      }
      return;
    }
    try {
      final server = await ResourceView.serverFactory();
      if (!mounted) return;
      final scheme =
          Theme.of(context).brightness == Brightness.dark ? 'dark' : 'light';
      final page = await WebViewEmbedPage.create(
        server.page.replace(queryParameters: {
          if (widget.path != null)
            'path': widget.path!
          else
            'subject': widget.subject,
          // The page's first paint is in the app's light or dark mode.
          'scheme': scheme,
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
      _reveal();
    }
  }

  /// Watches the page until its `main` shows [ResourceView.subject] with
  /// something in it other than a loading state, then posts `revealed` two
  /// frames later (so it is on screen). Gives up after 1.5 s and posts
  /// anyway: the page then shows its own loading state or an empty view.
  void _watchReveal() {
    if (_revealed || _revealWatched) return;
    _revealWatched = true;
    final subject = jsonEncode(widget.subject);
    unawaited(_page
        ?.runJavaScript('(function(){var s=$subject,t=Date.now();'
            'function done(){requestAnimationFrame(function(){'
            'requestAnimationFrame(function(){AtomicFlutter.postMessage('
            'JSON.stringify({method:"revealed",ms:Date.now()-t}))})})}'
            'function c(){var all=document.querySelectorAll("main"),m=null;'
            'for(var i=0;i<all.length;i++)if(all[i].getAttribute("about")===s)'
            'm=all[i];if((m&&m.children.length>1&&'
            '!m.querySelector("[role=status]"))||Date.now()-t>1500){done();'
            'return}setTimeout(c,16)}c()})()')
        .catchError((_) {}));
  }

  bool _revealWatched = false;

  /// Shows the web view: the placeholder fades out.
  void _reveal() {
    _revealCap?.cancel();
    if (_revealed) return;
    _revealed = true;
    if (_page != null && !kReleaseMode) {
      final path = _warm ? 'warm' : 'cold';
      Perf.span('resource revealed $path', _clock.elapsedMilliseconds);
      Perf.sinceTap('resource revealed $path');
    }
    if (mounted) setState(() {});
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
      // The page is still in the pool's slot this frame (it is taken while
      // this page builds; the slot lets go after that). Both rebuild in the
      // next frame and the web view moves over, still attached. Nothing is
      // lost: the placeholder covers it for the first frames anyway.
      _inTree = false;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) setState(() => _inTree = true);
      });
      debugPrint('[warm] taken ready=${page is WebViewEmbedPage ? page.age : 0}'
          ' ms after it started loading');
      final subject = jsonEncode(widget.subject);
      // What the spare rendered ahead is read from the store again: it may
      // have changed while the page was hidden.
      final ahead = WarmResourceWebView.shownAhead[page];
      final reload =
          ahead == null ? '' : 'e.changed&&e.changed([${jsonEncode(ahead)}]);';
      // `open` replaces the page's blank first entry, so back leaves the
      // resource; an older bundle only has `show`.
      unawaited(page.runJavaScript('(function(e){if(!e)return;$reload'
          '(e.open||e.show)($subject)})(window.atomicEmbed)'));
      _watchPainted();
      _revealCap?.cancel();
      _revealCap = Timer(ResourceView.revealWarm, _reveal);
      _watchReveal();
    }
  }

  bool _warm = false;
  int _traced = 0;

  /// Whether this page builds its web view (see [_attach]).
  bool _inTree = true;

  /// Debug and profile builds: `[perf] resource painted` once the page's
  /// main area shows the resource's title (two frames after, so it is on
  /// screen). Without a title, nothing is measured.
  void _watchPainted() {
    if (kReleaseMode || widget.title.isEmpty || _paintWatched) return;
    _paintWatched = true;
    final title = jsonEncode(widget.title);
    // The page also times itself: from this script (a warm page, just told
    // to open) or from its own load (cold), to the frame that shows the
    // title. That excludes getting the message to the app, which on the
    // emulator waits for the web view's GL frames.
    final since = _warm ? 'Date.now()' : 'Date.now()-performance.now()';
    unawaited(_page
        ?.runJavaScript('(function(){var t0=$since,s=Date.now();function c(){'
            'var m=document.querySelector("main");'
            'if(m&&m.innerText.indexOf($title)>=0){requestAnimationFrame('
            'function(){requestAnimationFrame(function(){'
            'AtomicFlutter.postMessage(JSON.stringify({method:"painted",'
            'ms:Date.now()-t0}))})});return}'
            'if(Date.now()-s<20000)setTimeout(c,16)}c()})()')
        .catchError((_) {}));
  }

  bool _paintWatched = false;

  void _pageLoaded() {
    _watchPainted();
    _watchReveal();
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
    shell.registerMenu(route, (anchor) {
      // The page's own coordinates: its right edge is the button's.
      final box = context.findRenderObject() as RenderBox?;
      final at = box == null || !box.hasSize
          ? anchor
          : anchor.shift(-box.localToGlobal(Offset.zero));
      _page?.runJavaScript(
          'window.atomicEmbed?.openMenu({x:${at.right},y:${at.top}})');
    });
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
    _revealCap?.cancel();
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
    if (request['method'] == 'revealed') {
      _reveal();
      return;
    }
    if (request['method'] == 'painted') {
      final path = _warm ? 'warm' : 'cold';
      Perf.span('resource painted $path', _clock.elapsedMilliseconds);
      Perf.sinceTap('resource painted $path');
      Perf.span('resource painted in page $path', request['ms'] as int? ?? -1);
      return;
    }
    final id = request['id'] as int;
    final method = request['method'] as String;
    if (method == 'openNative') {
      await _answerOpenNative(id, request['args']);
      return;
    }
    if (method == 'theme') {
      // The theme chosen on the settings page: the app's own screens follow.
      final args = request['args'];
      unawaited(AppThemeMode.choose(
          args is List && args.isNotEmpty ? '${args.first}' : ''));
      try {
        await _page?.runJavaScript(
            'window.__atomicReply($id,true,${jsonEncode('true')})');
      } catch (_) {}
      return;
    }
    final started = _clock.elapsedMilliseconds;
    var firstContent = false;
    String reply;
    // Writes show up in logcat, so what the page persists can be followed.
    if (kDebugMode && !_readMethods.contains(method)) {
      debugPrint('[embed] call $method (${message.length} chars)');
    }
    try {
      final args = jsonEncode(_withDrive(method, request['args']));
      final prefetched =
          widget.call == null ? _pool?.takePrefetched(method, args) : null;
      final answer = await (prefetched ??
          (widget.call ?? widget.api.embedCall)(method, args));
      reply = 'true,${jsonEncode(answer)}';
      if (_firstRead && method == 'getResourcesWithSnapshots') {
        _firstRead = false;
        debugPrint('[embed] first read at $started ms, answered in '
            '${_clock.elapsedMilliseconds - started} ms'
            '${prefetched != null ? ' (read on pointer-down)' : ''}');
        debugPrint(_warm
            ? '[warm] open ${_clock.elapsedMilliseconds} ms first content'
            : '[warm] cold open ${_clock.elapsedMilliseconds} ms first content');
        firstContent = true;
      }
    } catch (e) {
      reply = 'false,${jsonEncode('$e')}';
    }
    // Answered after this screen is gone too: a page that is closing still
    // waits on the store (signing, applying its last commit).
    final answered = _clock.elapsedMilliseconds;
    try {
      await _page?.runJavaScript('window.__atomicReply($id,$reply)');
      if (!kReleaseMode && _traced++ < 12) {
        // The first calls of a page, to see where an open spends its time.
        debugPrint('[perf] embed $method in at $started, answered at '
            '$answered, delivered at ${_clock.elapsedMilliseconds} ms '
            '(${reply.length} chars)');
      }
      if (firstContent && !kReleaseMode) {
        Perf.span('resource data ${_warm ? 'warm' : 'cold'}',
            _clock.elapsedMilliseconds);
      }
    } catch (e) {
      debugPrint('[embed] reply to $method not delivered: $e');
    }
  }

  /// `opened(subject)`: the page settled on a resource (reached by a link, a
  /// folder's child, one just created). The store notes it in this drive's
  /// Recents, so it gets the drive the page is shown in.
  List<Object?> _withDrive(String method, Object? args) {
    final list = args is List ? List<Object?>.of(args) : <Object?>[];
    if (method == 'opened') {
      return [list.isEmpty ? '' : list.first, widget.drive];
    }
    return list;
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
        unawaited(Navigator.of(context)
            .push(SlideBackRoute<void>(
              builder: (_) => openResourceView(
                  api: widget.api,
                  drive: widget.drive,
                  subject: subject,
                  title: title,
                  className: kind),
            ))
            // The native screen can have changed it (renamed a chat room):
            // the page reads it again.
            .then((_) => _page?.runJavaScript(
                'window.atomicEmbed?.changed(${jsonEncode([subject])})')));
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
          // A page of the app's own (settings) has no breadcrumb of a
          // resource, so it gets the title bar of the native screens.
          appBar: widget.path != null && widget.title.isNotEmpty
              ? AppTopBar(title: widget.title)
              : null,
          body: SafeArea(
            bottom: false,
            child: _error != null
                ? Center(
                    child: Text('$_error', style: TextStyle(color: c.alert)))
                : Stack(children: [
                    if (page != null && _inTree) page.build(),
                    if (!_skeletonGone)
                      Positioned.fill(
                        child: AnimatedOpacity(
                          opacity: _revealed ? 0 : 1,
                          duration: ResourceView.revealFade,
                          onEnd: () {
                            if (_revealed && mounted) {
                              setState(() => _skeletonGone = true);
                            }
                          },
                          child: ResourceSkeleton(title: widget.title),
                        ),
                      ),
                    // Next to the list the bar has no room for the resource's
                    // menu: it sits in the pane's top right corner.
                    if (widget.path == null &&
                        ShellScope.maybeOf(context) != null &&
                        ShellScope.layoutOf(context) == ShellLayout.split)
                      Positioned(
                        top: 0,
                        right: kEmbedNavBarTrailingInset,
                        child: ListenableBuilder(
                          listenable: ShellScope.maybeOf(context)!,
                          builder: (context, _) {
                            final onMore = ShellScope.maybeOf(context)!.topMenu;
                            if (onMore == null || _route?.isCurrent != true) {
                              return const SizedBox.shrink();
                            }
                            return Builder(
                              key: const ValueKey('more'),
                              builder: (button) => IconButton(
                                // As big as the web header it sits in
                                // (36 dp), not the 48 dp default.
                                iconSize: 20,
                                padding: EdgeInsets.zero,
                                visualDensity: VisualDensity.compact,
                                color: c.textSecondary,
                                constraints: const BoxConstraints(
                                    minWidth: kEmbedNavBarHeight,
                                    minHeight: kEmbedNavBarHeight),
                                style: IconButton.styleFrom(
                                  tapTargetSize:
                                      MaterialTapTargetSize.shrinkWrap,
                                  fixedSize: const Size.square(
                                      kEmbedNavBarHeight),
                                  minimumSize: const Size.square(
                                      kEmbedNavBarHeight),
                                ),
                                tooltip: 'More',
                                onPressed: () {
                                  final box =
                                      button.findRenderObject() as RenderBox;
                                  onMore(box.localToGlobal(Offset.zero) &
                                      box.size);
                                },
                                icon: const Icon(Icons.more_vert),
                              ),
                            );
                          },
                        ),
                      ),
                    // Swipe back starts at the left edge.
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

/// Height of the web page's header row (the embed's `HEADER_HEIGHT`), which
/// the native "more" button on a tablet sits in and is centred on.
const kEmbedNavBarHeight = 36.0;

/// Gap between the native "more" button and the pane's right edge: with the
/// button's 8 dp of inner space the icon sits 12 dp in, like the web header's
/// own padding.
const kEmbedNavBarTrailingInset = 4.0;

/// What a resource page shows until its web view shows the resource: the
/// page's background and its 36 px header row with the resource's title (as
/// the row it was opened from called it), so the page is there at once and
/// the web view's own header takes its place.
class ResourceSkeleton extends StatelessWidget {
  final String title;

  const ResourceSkeleton({super.key, required this.title});

  static const headerHeight = kEmbedNavBarHeight;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return ColoredBox(
      key: const Key('resource-skeleton'),
      color: c.bgBody,
      child: Align(
        alignment: Alignment.topLeft,
        child: Container(
          height: headerHeight,
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          alignment: Alignment.centerLeft,
          decoration: BoxDecoration(
            border: Border(bottom: BorderSide(color: c.bg2)),
          ),
          child: Text(
            title,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(color: c.textPrimary, fontSize: 15),
          ),
        ),
      ),
    );
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
