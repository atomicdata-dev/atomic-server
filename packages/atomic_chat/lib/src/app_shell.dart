import 'dart:async';
import 'dart:math' as math;

import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/scheduler.dart';

import 'covered_insets_freeze.dart';
import 'app_bottom_bar.dart';
import 'models.dart';
import 'assistant_api.dart';
import 'search_screen.dart';
import 'native_views.dart';
import 'warm_resource_web_view.dart';
import 'slide_back_route.dart';

/// The route names of the pages the bottom bar opens: a page's kind. The bar
/// shows which of its pages is on top and never stacks a second one of a
/// kind (see [ShellController.open]).
abstract final class ShellPage {
  static const home = 'home';
  static const search = 'search';

  /// A search in one drive is `search:<drive>`.
  static String searchIn(String drive) => '$search:$drive';
  static bool isSearch(String? kind) =>
      kind == search || (kind?.startsWith('$search:') ?? false);

  static const newChat = 'new-chat';
  static const voiceChat = 'voice-chat';
  static const newResource = 'new-resource';
  static const profile = 'profile';
  static const settings = 'settings';
}

/// How the shell arranges itself for the width of the window.
enum ShellLayout {
  /// A phone: the pages above a bottom bar.
  bar,

  /// Wider (a small tablet, a phone sideways): a navigation rail at the
  /// left instead of the bar, the pages beside it.
  rail,

  /// A tablet: the rail, the home (or search) as a list pane, and what is
  /// opened from it in a detail pane next to it.
  split;

  /// Widths (logical pixels) from which the [rail] and the [split] layouts
  /// are used.
  static const railWidth = 600.0;
  static const splitWidth = 720.0;

  static ShellLayout forWidth(double width) => width >= splitWidth
      ? split
      : width >= railWidth
          ? rail
          : bar;
}

/// Opens a page's menu; [anchor] is the bar button that asked, in global
/// coordinates, so the menu opens at that button.
typedef ShellMenu = void Function(Rect anchor);

/// What the bottom bar or the rail needs to know about the pages: which is
/// on top, what the list pane shows, which resource is selected. The shell
/// owns one; pages find it through [ShellScope].
class ShellController extends ChangeNotifier {
  /// The pages' navigator: the whole screen above the bar on a phone, the
  /// detail pane in the [ShellLayout.split] layout.
  final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

  /// The layout the shell was last built in. Widgets that look different per
  /// layout read [ShellScope.layoutOf] instead, which rebuilds them.
  ShellLayout layout = ShellLayout.bar;

  /// Whether the home is in a list pane with the pages next to it.
  bool get split => layout == ShellLayout.split;

  /// What the list pane shows in the [ShellLayout.split] layout: the home
  /// ([ShellPage.home]) or a search ([ShellPage.search],
  /// [ShellPage.searchIn]).
  final ValueNotifier<String> list = ValueNotifier(ShellPage.home);

  /// The subject of the resource the detail pane shows (what was opened
  /// from a list), for the list to mark its row; null when none.
  final ValueNotifier<String?> selected = ValueNotifier(null);

  /// The text and drive of the search that is open, so it survives a change
  /// of layout (it moves between a page and the list pane).
  ({String query, String? scope}) search = (query: '', scope: null);

  /// Pages opened for a resource ([openDetail]) and its subject.
  final Map<Route<dynamic>, String> _details = {};

  /// The drive search looks in; the home updates it.
  final ValueNotifier<String> drive;

  /// Opens the user's page; the home sets it (it handles sign-out). Without
  /// one the bar opens [profile].
  VoidCallback? onUser;

  /// Builds the user's page (agent, sync and account), which the host app
  /// owns. It pops with `true` when the person signed out there.
  final WidgetBuilder? profile;

  /// The web page kept loaded for the next resource (see
  /// [WarmResourceWebView]); null where there is none.
  WarmResourceWebView? warm;

  ShellController({String drive = '', this.profile})
      : drive = ValueNotifier(drive);

  /// What search last knew (drives and recently opened), so it can paint the
  /// list on its first frame and refresh behind it.
  SearchCache? searchCache;

  final Map<Route<dynamic>, ShellMenu> _menus = {};
  Route<dynamic>? _top;

  /// The page routes of the shell's navigator, bottom first.
  final List<Route<dynamic>> _stack = [];

  /// Kinds that changed after a page was opened (a new chat that got its
  /// first message is no longer a new chat).
  final Map<Route<dynamic>, String?> _kinds = {};

  /// The page route that is on top of the shell's navigator.
  Route<dynamic>? get top => _top;

  /// The kind ([ShellPage]) of [route]: its route name unless [setKind]
  /// changed it.
  String? kindOf(Route<dynamic> route) =>
      _kinds.containsKey(route) ? _kinds[route] : route.settings.name;

  /// The kind ([ShellPage]) of the page on top, if it has one.
  String? get topKind => _top == null ? null : kindOf(_top!);

  /// Whether the first page (the home) is the one showing.
  bool get atHome => _stack.length <= 1;

  /// Whether a page of [kind] is anywhere in the stack.
  bool hasPage(String kind) => _stack.any((r) => kindOf(r) == kind);

  /// The pages above the first one, bottom first.
  List<Route<dynamic>> get pages => _stack.skip(1).toList();

  /// [route] is a page of [kind] from now on (null: of none). A route that
  /// is not one of the shell's pages (the list pane is in none) is ignored.
  void setKind(Route<dynamic> route, String? kind) {
    if (!_stack.contains(route)) return;
    if (_kinds.containsKey(route) && _kinds[route] == kind) return;
    _kinds[route] = kind;
    if (identical(route, _top)) _changed();
  }

  /// A push from the bar happened a moment ago: a second tap is ignored.
  Timer? _settling;

  /// Opens the page of [kind] the bar asks for, at most once: when it is on
  /// top already the page's [onReselect] action runs (a new chat's field
  /// gets the cursor), and nothing happens while a push is under way (a
  /// double tap), and when it is further down the stack the pages above it are
  /// popped instead of a second one pushed. Answers what the pushed page pops
  /// with; null when nothing was pushed.
  Future<T?> open<T>(
      String kind, Route<T> Function(RouteSettings settings) route) async {
    final navigator = navigatorKey.currentState;
    if (navigator == null || _settling != null) return null;
    if (topKind == kind) {
      _reselect[_top]?.call();
      return null;
    }
    if (hasPage(kind)) {
      navigator.popUntil((r) => kindOf(r) == kind);
      return null;
    }
    _settling =
        Timer(const Duration(milliseconds: 300), () => _settling = null);
    return _show(navigator, route(RouteSettings(name: kind)));
  }

  /// Pushes [route]; next to the list it takes the place of what the detail
  /// pane showed (a row opens there; it does not pile up).
  Future<T?> _show<T>(NavigatorState navigator, Route<T> route) => split
      ? navigator.pushAndRemoveUntil(route, (r) => r.isFirst)
      : navigator.push(route);

  /// Opens the page of a resource picked from a list (the home, search):
  /// pushed on a phone, in the detail pane next to the list. [subject] marks
  /// its row as the selected one. Picking the row that is shown already
  /// does nothing.
  Future<T?> openDetail<T>(WidgetBuilder builder, {String? subject}) async {
    final navigator = navigatorKey.currentState;
    if (navigator == null) return null;
    if (split && subject != null && _top != null && _details[_top] == subject) {
      return null;
    }
    // Next to the list the pane just shows it: no slide to wait for.
    final route = SlideBackRoute<T>(builder: builder, instant: split);
    if (subject != null) _details[route] = subject;
    return _show(navigator, route);
  }

  /// Shows [kind] in the list pane ([ShellPage.home] or a search); only in
  /// the split layout.
  void showList(String kind) {
    if (list.value == kind) return;
    if (ShellPage.isSearch(kind)) {
      search = (
        query: '',
        scope: kind == ShellPage.search
            ? null
            : kind.substring(ShellPage.search.length + 1)
      );
    }
    list.value = kind;
    _changed();
  }

  /// [open] with the page sliding in from the right.
  Future<T?> openPage<T>(String kind, WidgetBuilder builder) => open<T>(kind,
      (settings) => SlideBackRoute<T>(builder: builder, settings: settings));

  /// Back to the first page.
  void goHome() =>
      navigatorKey.currentState?.popUntil((route) => route.isFirst);

  /// The menu action of the page on top, if that page has one.
  ShellMenu? get topMenu => _top == null ? null : _menus[_top];

  /// A page with a resource menu registers it under its own route. It only
  /// counts while that route is the top one.
  void registerMenu(Route<dynamic> route, ShellMenu onMore) {
    _menus[route] = onMore;
    _changed();
  }

  final Map<Route<dynamic>, VoidCallback> _reselect = {};

  /// What a tap on the bar's button of [route]'s kind does while [route] is
  /// on top (instead of opening a second one).
  void onReselect(Route<dynamic> route, VoidCallback action) =>
      _reselect[route] = action;

  void unregisterMenu(Route<dynamic> route) {
    if (_menus.remove(route) != null) _changed();
  }

  void _pushed(Route<dynamic> route) {
    _stack.add(route);
    _setTop(route);
  }

  void _removed(Route<dynamic> route) {
    _stack.remove(route);
    _kinds.remove(route);
    _menus.remove(route);
    _reselect.remove(route);
    if (_details.remove(route) != null) _changed();
  }

  void _setTop(Route<dynamic>? route) {
    if (identical(route, _top)) return;
    _top = route;
    _changed();
  }

  /// The subject of the topmost page opened for a resource.
  String? get _selectedNow {
    for (final route in _stack.reversed) {
      final subject = _details[route];
      if (subject != null) return subject;
    }
    return null;
  }

  // Navigator observers run while the navigator is building at times (its
  // first route), and a listener must not rebuild then.
  void _changed() {
    if (_disposed) return;
    void notify() {
      if (_disposed) return;
      selected.value = _selectedNow;
      notifyListeners();
    }

    if (SchedulerBinding.instance.schedulerPhase ==
        SchedulerPhase.persistentCallbacks) {
      SchedulerBinding.instance.addPostFrameCallback((_) => notify());
    } else {
      notify();
    }
  }

  bool _disposed = false;

  @override
  void dispose() {
    _disposed = true;
    _settling?.cancel();
    drive.dispose();
    list.dispose();
    selected.dispose();
    super.dispose();
  }
}

/// Finds the [ShellController] of the shell a page is in, if any, and the
/// shell's [ShellLayout].
class ShellScope extends InheritedWidget {
  final ShellController controller;
  final ShellLayout layout;

  const ShellScope({
    super.key,
    required this.controller,
    this.layout = ShellLayout.bar,
    required super.child,
  });

  static ShellController? maybeOf(BuildContext context) =>
      context.getInheritedWidgetOfExactType<ShellScope>()?.controller;

  /// The shell's layout ([ShellLayout.bar] outside a shell); the caller is
  /// rebuilt when it changes.
  static ShellLayout layoutOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<ShellScope>()?.layout ??
      ShellLayout.bar;

  @override
  bool updateShouldNotify(ShellScope old) =>
      controller != old.controller || layout != old.layout;
}

/// Opens a resource's page picked from a list: through the shell when there
/// is one ([ShellController.openDetail]: the detail pane next to the list),
/// else pushed on the nearest navigator.
Future<T?> openFromList<T>(BuildContext context, WidgetBuilder builder,
    {String? subject}) {
  final shell = ShellScope.maybeOf(context);
  if (shell != null && shell.navigatorKey.currentState != null) {
    return shell.openDetail<T>(builder, subject: subject);
  }
  return Navigator.of(context).push(SlideBackRoute<T>(builder: builder));
}

/// Tracks which page route is on top of the shell's navigator. Dialogs and
/// menus (not page routes) do not count: the bar follows the page below.
class _TopObserver extends NavigatorObserver {
  final ShellController shell;

  _TopObserver(this.shell);

  @override
  void didPush(Route<dynamic> route, Route<dynamic>? previousRoute) {
    if (route is PageRoute) shell._pushed(route);
  }

  @override
  void didPop(Route<dynamic> route, Route<dynamic>? previousRoute) {
    if (route is! PageRoute) return;
    shell._removed(route);
    if (previousRoute is PageRoute) shell._setTop(previousRoute);
  }

  @override
  void didRemove(Route<dynamic> route, Route<dynamic>? previousRoute) {
    if (route is! PageRoute) return;
    final wasTop = identical(route, shell.top);
    shell._removed(route);
    if (wasTop && previousRoute is PageRoute) shell._setTop(previousRoute);
  }

  @override
  void didReplace({Route<dynamic>? newRoute, Route<dynamic>? oldRoute}) {
    if (oldRoute is PageRoute) {
      final at = shell._stack.indexOf(oldRoute);
      shell._removed(oldRoute);
      if (newRoute is PageRoute && at >= 0) shell._stack.insert(at, newRoute);
    }
    if (newRoute is PageRoute && identical(newRoute, shell._stack.lastOrNull)) {
      shell._setTop(newRoute);
    }
  }
}

/// The logged-in app: the pages in a nested navigator above a bottom bar that
/// never moves. Only the part above the bar slides when a page is pushed.
class AppShell extends StatefulWidget {
  final AssistantApi api;

  /// The drive search starts in.
  final String drive;

  /// The first page.
  final Widget home;

  /// The pre-loaded web page; by default one is made on a phone and none
  /// elsewhere. A test passes its own (or none).
  final WarmResourceWebView? Function(AssistantApi api)? warmPool;

  /// The user's page the Profile button opens (see [ShellController.profile]).
  final WidgetBuilder? profile;

  const AppShell({
    super.key,
    required this.api,
    required this.drive,
    required this.home,
    this.profile,
    this.warmPool,
  });

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  late final ShellController _shell =
      ShellController(drive: widget.drive, profile: widget.profile);
  late final _TopObserver _observer = _TopObserver(_shell);

  /// The home keeps its state wherever it is shown: as the first page, or in
  /// the list pane next to the pages.
  final GlobalKey _homeKey = GlobalKey(debugLabel: 'home');
  late final Widget _home = KeyedSubtree(key: _homeKey, child: widget.home);

  /// One instance for the life of the shell: the keyboard animation rebuilds
  /// the tiny widgets around it, never the pages. Its key keeps it (and every
  /// page in it) when a change of layout moves it.
  late final Widget _navigator = Navigator(
    key: _shell.navigatorKey,
    observers: [_observer],
    onGenerateRoute: (_) => MaterialPageRoute<void>(
      settings: const RouteSettings(name: ShellPage.home),
      builder: (_) => CoveredInsetsFreeze(child: _HomeSlot(home: _home)),
    ),
  );

  final ValueNotifier<double> _barHeight = ValueNotifier(0);

  late final Widget _bar =
      _FrozenBottomPadding(child: AppBottomBar(api: widget.api, shell: _shell));

  /// Under the rail and the panes: the system's bottom inset (the gesture
  /// handle, a taskbar) in the bar's colour, kept while the keyboard is up
  /// as the bar is.
  late final Widget _strip = const _FrozenBottomPadding(child: _BottomStrip());

  late final Widget _rail = AppNavRail(api: widget.api, shell: _shell);

  late final Widget _detail = _Pane(
    removeLeft: true,
    child: Stack(children: [
      ..._spareUnderPages,
      Positioned.fill(child: _navigator),
      _DetailMore(shell: _shell),
    ]),
  );

  /// The pages on a phone: the navigator, with the warm page under it.
  late final Widget _phonePages = Stack(children: [
    ..._spareUnderPages,
    Positioned.fill(child: _navigator),
  ]);

  /// The warm page ([WarmPageSlot]), filling the box the pages fill, so it is
  /// laid out at the size a resource page will give it. It moves with a
  /// change of layout (its key), like the navigator.
  List<Widget> get _spareUnderPages => [
        if (_shell.warm != null)
          Positioned.fill(child: WarmPageSlot(pool: _shell.warm!)),
      ];

  late final Widget _listPane = _Pane(
    removeLeft: true,
    removeRight: true,
    child: _ListPane(shell: _shell, api: widget.api, home: _home),
  );

  @override
  void initState() {
    super.initState();
    // The shell exists once the person is in and the host's store is open:
    // load the next resource's page now, while they look at the home.
    _shell.warm =
        (widget.warmPool ?? WarmResourceWebView.forPlatform)(widget.api)
          ?..showAhead = _likelyNext
          ..warmUp();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // The spare paints in the app's light or dark mode before it is taken.
    _shell.warm?.colorScheme =
        Theme.of(context).brightness == Brightness.dark ? 'dark' : 'light';
  }

  /// The latest of Recents, when the page shows it (a native view does not).
  Future<String?> _likelyNext() async {
    final drive = _shell.drive.value;
    if (drive.isEmpty) return null;
    final recent = await widget.api.recentResources(drive);
    for (final r in recent) {
      if (!hasNativeView(r.className)) return r.subject;
    }
    return null;
  }

  @override
  void dispose() {
    _shell.warm?.dispose();
    _shell.dispose();
    _barHeight.dispose();
    super.dispose();
  }

  /// After a change of layout, a search moves between a page (bar, rail)
  /// and the list pane (split), keeping its text and drive.
  void _relayout(ShellLayout from, ShellLayout to) {
    if (!mounted || _shell.layout != to) return;
    final navigator = _shell.navigatorKey.currentState;
    if (navigator == null) return;
    final wasSplit = from == ShellLayout.split;
    final isSplit = to == ShellLayout.split;
    if (!wasSplit && isSplit) {
      final searches = [
        for (final r in _shell.pages)
          if (ShellPage.isSearch(_shell.kindOf(r))) r
      ];
      if (searches.isEmpty) return;
      final kind = _shell.kindOf(searches.last)!;
      for (final r in searches) {
        navigator.removeRoute(r);
      }
      _shell.list.value = kind;
    } else if (wasSplit && !isSplit) {
      final kind = _shell.list.value;
      _shell.list.value = ShellPage.home;
      if (!ShellPage.isSearch(kind)) return;
      final search = _shell.search;
      _shell.open<void>(
          kind,
          (settings) => SearchScreen.route(
              drive: _shell.drive.value,
              api: widget.api,
              scopeDrive: search.scope,
              initialQuery: search.query,
              settings: settings));
    }
  }

  /// Back with nothing left to close in the pages: a search in the list
  /// pane goes back to the home first.
  bool get _listCanPop => !_shell.split || _shell.list.value == ShellPage.home;

  @override
  Widget build(BuildContext context) {
    final layout = ShellLayout.forWidth(MediaQuery.sizeOf(context).width);
    if (layout != _shell.layout) {
      final from = _shell.layout;
      _shell.layout = layout;
      WidgetsBinding.instance
          .addPostFrameCallback((_) => _relayout(from, layout));
    }
    final Widget pages = switch (layout) {
      ShellLayout.bar => _phonePages,
      ShellLayout.rail => Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [_rail, Expanded(child: _detail)]),
      ShellLayout.split => LayoutBuilder(
          builder: (context, box) =>
              Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            _rail,
            SizedBox(
                width: _listWidth(box.maxWidth - AppNavRail.width),
                child: _listPane),
            const _PaneDivider(),
            Expanded(child: _detail),
          ]),
        ),
    };
    return ShellScope(
      controller: _shell,
      layout: layout,
      child: ValueListenableBuilder<String>(
        valueListenable: _shell.list,
        builder: (context, _, child) => PopScope(
          canPop: _listCanPop,
          onPopInvokedWithResult: (didPop, _) {
            if (didPop) return;
            if (_shell.navigatorKey.currentState?.canPop() ?? false) return;
            _shell.showList(ShellPage.home);
          },
          child: child!,
        ),
        // Android back pops the pages first and leaves the app on the home.
        child: NavigatorPopHandler(
          onPopWithResult: (_) => _shell.navigatorKey.currentState?.maybePop(),
          child: Column(children: [
            // The bar stays laid out at full height; the keyboard covers it
            // and the pages get the keyboard minus the bar's height.
            Expanded(child: _PagesInset(barHeight: _barHeight, child: pages)),
            _MeasureHeight(
                height: _barHeight,
                child: layout == ShellLayout.bar ? _bar : _strip),
          ]),
        ),
      ),
    );
  }
}

/// The list pane's width next to the pages: about two fifths of the room,
/// at least a phone's narrowest list and at most what a list needs.
double _listWidth(double room) => (room * 0.4).clamp(280.0, 380.0);

/// The first page: the home on a phone; in the split layout the home is in
/// the list pane, and this shows that nothing is opened yet.
class _HomeSlot extends StatelessWidget {
  final Widget home;

  const _HomeSlot({required this.home});

  @override
  Widget build(BuildContext context) =>
      ShellScope.layoutOf(context) == ShellLayout.split
          ? const _NothingOpen()
          : home;
}

/// The detail pane before anything is opened.
class _NothingOpen extends StatelessWidget {
  const _NothingOpen();

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      key: const Key('nothing-open'),
      backgroundColor: c.bgBody,
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.article_outlined, size: 40, color: c.textSecondary),
            const SizedBox(height: 12),
            Text('Open something from the list',
                textAlign: TextAlign.center,
                style: TextStyle(color: c.textSecondary)),
          ]),
        ),
      ),
    );
  }
}

/// The list pane: the home, or a search over it. The home stays built (and
/// keeps its scroll and folds) while a search is shown.
class _ListPane extends StatelessWidget {
  final ShellController shell;
  final AssistantApi api;
  final Widget home;

  const _ListPane({required this.shell, required this.api, required this.home});

  @override
  Widget build(BuildContext context) => ValueListenableBuilder<String>(
        valueListenable: shell.list,
        builder: (context, kind, _) {
          final searching = ShellPage.isSearch(kind);
          return Stack(children: [
            Positioned.fill(
              child: Offstage(
                offstage: searching,
                child: TickerMode(
                  enabled: !searching,
                  // The home only moves for the keyboard of its own pages.
                  child: MediaQuery.removeViewInsets(
                      context: context, removeBottom: true, child: home),
                ),
              ),
            ),
            if (searching)
              Positioned.fill(
                child: SearchScreen(
                  key: ValueKey(kind),
                  drive: shell.drive.value,
                  api: api,
                  scopeDrive: shell.search.scope,
                  initialQuery: shell.search.query,
                ),
              ),
          ]);
        },
      );
}

/// A pane of the wide layouts: the system insets of the sides it does not
/// touch are not its business (the rail takes the left one).
class _Pane extends StatelessWidget {
  final bool removeLeft;
  final bool removeRight;
  final Widget child;

  const _Pane({
    this.removeLeft = false,
    this.removeRight = false,
    required this.child,
  });

  @override
  Widget build(BuildContext context) => MediaQuery.removePadding(
        context: context,
        removeLeft: removeLeft,
        removeRight: removeRight,
        child: child,
      );
}

class _PaneDivider extends StatelessWidget {
  const _PaneDivider();

  /// The theme's divider: a hairline that is quiet in light and dark.
  @override
  Widget build(BuildContext context) => ColoredBox(
      color: Theme.of(context).colorScheme.outlineVariant,
      child: const SizedBox(width: 1));
}

/// The bottom system inset under the rail and the panes, in the bar's
/// colour (the system navigation bar has it too).
class _BottomStrip extends StatelessWidget {
  const _BottomStrip();

  @override
  Widget build(BuildContext context) => ColoredBox(
        color: context.appColors.barSurface,
        child: SizedBox(
            width: double.infinity,
            height: MediaQuery.paddingOf(context).bottom),
      );
}

/// The "more" menu of the resource the detail pane shows, at the pane's top
/// right (on a phone it is the bar's last button). The page's own header
/// row is 36 high; the button sits in it.
class _DetailMore extends StatelessWidget {
  final ShellController shell;

  const _DetailMore({required this.shell});

  @override
  Widget build(BuildContext context) {
    final padding = MediaQuery.paddingOf(context);
    return Positioned(
      top: padding.top,
      right: padding.right,
      child: ListenableBuilder(
        listenable: shell,
        builder: (context, _) {
          final onMore = shell.topMenu;
          if (onMore == null) return const SizedBox.shrink();
          return Builder(
            builder: (button) => SizedBox(
              width: 48,
              height: 36,
              child: IconButton(
                key: const Key('detail-more'),
                tooltip: 'More',
                padding: EdgeInsets.zero,
                onPressed: () {
                  final box = button.findRenderObject() as RenderBox;
                  onMore(box.localToGlobal(Offset.zero) & box.size);
                },
                icon: const Icon(Icons.more_vert),
              ),
            ),
          );
        },
      ),
    );
  }
}

/// The pages' region ends above the bar, but the keyboard is drawn over the
/// bar, not above it. So the pages must see the keyboard minus the bar's
/// height: their bodies then end exactly at the keyboard's top, and the keyboard
/// and the bar move together with nothing else animating. The bar's own system
/// inset is not the pages' business either. Only this widget follows
/// MediaQuery; its child is stable.
class _PagesInset extends StatelessWidget {
  final ValueListenable<double> barHeight;
  final Widget child;

  const _PagesInset({required this.barHeight, required this.child});

  @override
  Widget build(BuildContext context) {
    final media = MediaQuery.of(context);
    return ValueListenableBuilder<double>(
      valueListenable: barHeight,
      child: child,
      builder: (context, bar, child) => MediaQuery(
        data: media.copyWith(
          padding: media.padding.copyWith(bottom: 0),
          viewPadding: media.viewPadding.copyWith(bottom: 0),
          viewInsets: media.viewInsets
              .copyWith(bottom: math.max(0, media.viewInsets.bottom - bar)),
        ),
        child: child!,
      ),
    );
  }
}

/// Gives the bar a bottom system inset that does not shrink while the keyboard
/// animates (on Android `padding.bottom` drops to 0 with the keyboard, which
/// would resize the bar mid-animation). It remembers the largest one seen, and
/// forgets it when the orientation changes.
class _FrozenBottomPadding extends StatefulWidget {
  final Widget child;

  const _FrozenBottomPadding({required this.child});

  @override
  State<_FrozenBottomPadding> createState() => _FrozenBottomPaddingState();
}

class _FrozenBottomPaddingState extends State<_FrozenBottomPadding> {
  double _bottom = 0;
  Orientation? _orientation;

  @override
  Widget build(BuildContext context) {
    final media = MediaQuery.of(context);
    if (media.orientation != _orientation) {
      _orientation = media.orientation;
      _bottom = 0;
    }
    _bottom = math.max(_bottom, math.max(media.padding.bottom, 0));
    return MediaQuery(
      data: media.copyWith(padding: media.padding.copyWith(bottom: _bottom)),
      child: widget.child,
    );
  }
}

/// Reports the height of its child after layout, without a layout loop: the
/// notifier is written in a post-frame callback and only when it changed.
class _MeasureHeight extends SingleChildRenderObjectWidget {
  final ValueNotifier<double> height;

  const _MeasureHeight({required this.height, required super.child});

  @override
  RenderObject createRenderObject(BuildContext context) =>
      _RenderMeasureHeight(height);

  @override
  void updateRenderObject(
      BuildContext context, _RenderMeasureHeight renderObject) {
    renderObject.height = height;
  }
}

class _RenderMeasureHeight extends RenderProxyBox {
  ValueNotifier<double> height;

  _RenderMeasureHeight(this.height);

  @override
  void performLayout() {
    super.performLayout();
    final h = size.height;
    if (h == height.value) return;
    SchedulerBinding.instance.addPostFrameCallback((_) {
      if (attached && height.value != h) height.value = h;
    });
  }
}

/// Drives and recently opened resources as search last saw them.
class SearchCache {
  final List<DriveInfo> drives;
  final List<({String drive, RecentResource resource})> recent;

  const SearchCache(this.drives, this.recent);
}
