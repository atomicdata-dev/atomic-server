import 'dart:async';
import 'dart:math' as math;

import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt, HoldFan;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/scheduler.dart';
import 'package:shared_preferences/shared_preferences.dart';

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

  /// A search for one kind of resource is `search@<kind>`.
  static String searchOf(SearchKind kind) =>
      kind == SearchKind.any ? search : '$search@${kind.name}';

  /// The page of a search in [scope] for [kind].
  static String searchFor({String? scope, SearchKind kind = SearchKind.any}) =>
      kind != SearchKind.any
          ? searchOf(kind)
          : scope == null
              ? search
              : searchIn(scope);

  static bool isSearch(String? kind) =>
      kind == search ||
      (kind?.startsWith('$search:') ?? false) ||
      (kind?.startsWith('$search@') ?? false);

  /// The full list of a home section (its "All" button) is `list:<name>`.
  static String listOf(String section) => 'list:$section';
  static bool isList(String? kind) => kind?.startsWith('list:') ?? false;

  static const newChat = 'new-chat';
  static const voiceChat = 'voice-chat';
  static const newResource = 'new-resource';
  static const profile = 'profile';
  static const settings = 'settings';
}

/// How the shell arranges itself for the width of the window. Both have the
/// same bottom bar: the width of the window on a phone, of the sidebar (the
/// list pane) next to the pages.
enum ShellLayout {
  /// A phone: the pages above the bottom bar.
  bar,

  /// A tablet, a phone sideways: above the bar the home (or a search) as a
  /// list pane, which folds away, and what is opened from it in a detail
  /// pane next to it.
  split;

  /// The width (logical pixels) from which the [split] layout is used.
  static const splitWidth = 600.0;

  static ShellLayout forWidth(double width) =>
      width >= splitWidth ? split : bar;
}

/// SharedPreferences key of the list pane's dragged width (per device). Its
/// fold is not kept: every start shows the list (a fold left behind once made
/// the Samsung tablet start on an empty page with nothing to go back to).
const listWidthKey = 'shell_list_width';

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

  /// The text, drive and kind of the search that is open, so it survives a
  /// change of layout (it moves between a page and the list pane).
  ({String query, String? scope, SearchKind kind}) search =
      (query: '', scope: null, kind: SearchKind.any);

  /// The list pane is folded away: the detail pane has the whole window.
  /// Kept through resizes and rotation, not across starts.
  final ValueNotifier<bool> listCollapsed = ValueNotifier(false);

  /// The list pane's width the person dragged it to; null: one that suits
  /// the window. Remembered per device ([listWidthKey]).
  final ValueNotifier<double?> listWidth = ValueNotifier(null);

  /// Folds the list pane away, or brings it back.
  void setListCollapsed(bool collapsed) {
    if (listCollapsed.value == collapsed) return;
    listCollapsed.value = collapsed;
    _changed();
  }

  void setListWidth(double width) {
    listWidth.value = width;
    _savePrefs((p) => p.setDouble(listWidthKey, width));
  }

  /// Reads the list pane's width as this device left it.
  Future<void> loadListPrefs() async {
    try {
      final p = await SharedPreferences.getInstance();
      if (_disposed) return;
      listWidth.value = p.getDouble(listWidthKey);
      _changed();
    } catch (_) {
      // The default: a width that suits the window.
    }
  }

  static void _savePrefs(Future<void> Function(SharedPreferences) write) {
    SharedPreferences.getInstance().then(write).catchError((Object _) {});
  }

  /// Counts taps on the Search button while a search is open (or was popped
  /// back to): the search on top empties its field ([resetSearch]).
  final ValueNotifier<int> searchReset = ValueNotifier(0);

  /// The Search button again: the open search starts over (empty field, the
  /// keyboard up; its drive is kept unless the field was empty already).
  void resetSearch() {
    search = (query: '', scope: search.scope, kind: search.kind);
    searchReset.value++;
  }

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

  /// Who the person is, for the bar's profile button; null until loaded (the
  /// button then shows a person icon). Kept once loaded: a failed refresh
  /// leaves the last one.
  final ValueNotifier<ProfileIdentity?> identity = ValueNotifier(null);

  /// Reads the identity ([AppShell] sets it to the api's [AssistantApi.ownIdentity]).
  Future<ProfileIdentity?> Function()? identityLoader;

  int _identityLoads = 0;

  /// Loads the identity again (after the profile was edited, on resume).
  Future<void> refreshIdentity() async {
    final load = identityLoader;
    if (load == null) return;
    final n = ++_identityLoads;
    try {
      final who = await load();
      // The latest request wins.
      if (_disposed || n != _identityLoads) return;
      if (who != null) identity.value = who;
    } catch (_) {
      // The last one stays.
    }
  }

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
  /// pane showed (a row opens there; it does not pile up). A resource
  /// ([overList]) opened from a section's full list ([ShellPage.isList])
  /// goes over it, and back returns to the list.
  Future<T?> _show<T>(NavigatorState navigator, Route<T> route,
          {bool overList = false}) =>
      split && !(overList && ShellPage.isList(topKind))
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
    return _show(navigator, route, overList: true);
  }

  /// Shows [kind] in the list pane ([ShellPage.home] or a search); only in
  /// the split layout. A folded list pane comes back.
  void showList(String kind) {
    setListCollapsed(false);
    if (list.value == kind) return;
    if (ShellPage.isSearch(kind)) {
      final rest = kind == ShellPage.search
          ? ''
          : kind.substring(ShellPage.search.length + 1);
      final ofKind = kind.startsWith('${ShellPage.search}@');
      search = (
        query: '',
        scope: ofKind || rest.isEmpty ? null : rest,
        kind: ofKind
            ? SearchKind.values
                .firstWhere((k) => k.name == rest, orElse: () => SearchKind.any)
            : SearchKind.any,
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
    final before = topKind;
    _top = route;
    // Coming back from (or into) the profile pages: the profile may have been
    // edited there.
    if (before == ShellPage.profile || topKind == ShellPage.profile) {
      refreshIdentity();
    }
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
    identity.dispose();
    list.dispose();
    listCollapsed.dispose();
    listWidth.dispose();
    selected.dispose();
    searchReset.dispose();
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

class _AppShellState extends State<AppShell> with WidgetsBindingObserver {
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

  /// The same bar in both layouts: the width of the window on a phone, at
  /// the foot of the list pane next to the pages. Keyed: a change of layout
  /// moves it without rebuilding it.
  final GlobalKey _barKey = GlobalKey(debugLabel: 'bar');
  late final Widget _bar = KeyedSubtree(
    key: _barKey,
    child: _MeasureHeight(
      height: _barHeight,
      child: _FrozenBottomPadding(
          child: AppBottomBar(api: widget.api, shell: _shell)),
    ),
  );

  /// The pages: the navigator, with the warm page under it. The whole room
  /// above the bar on a phone, the detail pane next to the list.
  late final Widget _pages = Stack(children: [
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
    _shell.loadListPrefs();
    _shell.identityLoader = widget.api.ownIdentity;
    _shell.refreshIdentity();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _shell.refreshIdentity();
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
    WidgetsBinding.instance.removeObserver(this);
    _shell.warm?.dispose();
    _shell.dispose();
    _barHeight.dispose();
    super.dispose();
  }

  /// After a change of layout, a search moves between a page (bar) and the
  /// list pane (split), keeping its text, drive and kind.
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
              kind: search.kind,
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
      ShellLayout.bar => _pages,
      ShellLayout.split => _SplitPanes(
          shell: _shell,
          list: _listPane,
          detail: _pages,
          bar: _bar,
          barHeight: _barHeight),
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
          onPopWithResult: (_) {
            // Back closes an open New (or Search) list before a page.
            if (HoldFan.dismissOpenMenu()) return;
            _shell.navigatorKey.currentState?.maybePop();
          },
          child: layout == ShellLayout.split
              // The bar is under the list pane only (see _SplitPanes).
              ? pages
              : Column(children: [
                  // The bar stays laid out at full height; the keyboard covers
                  // it and the pages get the keyboard minus the bar's height.
                  Expanded(
                      child: _PagesInset(barHeight: _barHeight, child: pages)),
                  _bar,
                ]),
        ),
      ),
    );
  }
}

/// The list pane's width next to the pages: about two fifths of the room,
/// 320 to 400, or the width it was dragged to; the pages keep at least
/// [_minDetail].
double listPaneWidth(double room, {double? dragged}) {
  final max = math.max(_minList, math.min(_maxDragged, room - _minDetail));
  return (dragged ?? (room * 0.4).clamp(320.0, 400.0))
      .clamp(_minList, max)
      .toDouble();
}

/// Room for the bar's six 48 dp slots and its padding.
const _minList = 304.0;
const _maxDragged = 520.0;
const _minDetail = 280.0;

/// How long the list pane takes to fold away or come back.
const listFoldDuration = Duration(milliseconds: 140);

/// The list pane and the detail pane side by side, with the divider between
/// them: a tap on its handle folds the list away (the pages get the whole
/// width) or brings it back, a drag makes it wider or narrower, and a drag
/// far to the left folds it. Both panes stay built while it moves.
class _SplitPanes extends StatefulWidget {
  final ShellController shell;
  final Widget list;
  final Widget detail;

  /// The bottom bar: at the foot of the list pane, exactly its width; it
  /// slides away with it (folded, the pages have the whole window).
  final Widget bar;
  final ValueListenable<double> barHeight;

  const _SplitPanes({
    required this.shell,
    required this.list,
    required this.detail,
    required this.bar,
    required this.barHeight,
  });

  @override
  State<_SplitPanes> createState() => _SplitPanesState();
}

class _SplitPanesState extends State<_SplitPanes>
    with SingleTickerProviderStateMixin {
  late final AnimationController _open = AnimationController(
    vsync: this,
    duration: listFoldDuration,
    value: widget.shell.listCollapsed.value ? 0 : 1,
  );

  /// The width while the divider is being dragged.
  double? _dragging;

  @override
  void initState() {
    super.initState();
    widget.shell.listCollapsed.addListener(_fold);
  }

  @override
  void dispose() {
    widget.shell.listCollapsed.removeListener(_fold);
    _open.dispose();
    super.dispose();
  }

  void _fold() {
    final collapsed = widget.shell.listCollapsed.value;
    _open.animateTo(collapsed ? 0 : 1, curve: Curves.easeOutCubic);
  }

  void _toggle() =>
      widget.shell.setListCollapsed(!widget.shell.listCollapsed.value);

  void _dragStart(double full) {
    final collapsed = widget.shell.listCollapsed.value;
    setState(() => _dragging = collapsed ? 0 : full);
  }

  void _dragUpdate(DragUpdateDetails d, double room) {
    final w = _dragging;
    if (w == null) return;
    setState(() => _dragging = (w + d.delta.dx).clamp(0.0, room - _minDetail));
  }

  /// A fling faster than this (dp/s) opens or folds the list whatever the
  /// distance.
  static const _fling = 300.0;

  void _dragEnd(double room, double velocity) {
    final w = _dragging;
    setState(() => _dragging = null);
    if (w == null) return;
    final shell = widget.shell;
    final full = listPaneWidth(room, dragged: shell.listWidth.value);
    if (shell.listCollapsed.value) {
      // Opening from the edge: follows the finger, then settles open (past a
      // third of the way, or flung right) or back.
      _open.value = (w / full).clamp(0.0, 1.0);
      if (velocity > _fling || (velocity > -_fling && w > full / 3)) {
        shell.setListCollapsed(false);
        _open.animateTo(1, curve: Curves.easeOutCubic);
      } else {
        _open.animateTo(0, curve: Curves.easeOutCubic);
      }
      return;
    }
    if (velocity < -_fling && w < full) {
      // Flung left: fold from where the finger left it.
      _open.value = (w / full).clamp(0.0, 1.0);
      shell.setListCollapsed(true);
      return;
    }
    if (w < _minList * 0.6) {
      // From where the finger left it.
      final full = listPaneWidth(room, dragged: shell.listWidth.value);
      _open.value = (w / full).clamp(0.0, 1.0);
      if (shell.listCollapsed.value) {
        _open.animateTo(0, curve: Curves.easeOutCubic);
      }
      shell.setListCollapsed(true);
      return;
    }
    shell.setListWidth(listPaneWidth(room, dragged: w));
    _open.value = 1;
    shell.setListCollapsed(false);
  }

  @override
  Widget build(BuildContext context) {
    final shell = widget.shell;
    return LayoutBuilder(builder: (context, box) {
      final room = box.maxWidth;
      return ValueListenableBuilder<double?>(
        valueListenable: shell.listWidth,
        builder: (context, dragged, _) {
          final full = listPaneWidth(room, dragged: dragged);
          return AnimatedBuilder(
            animation: _open,
            builder: (context, _) {
              final dragging = _dragging;
              final listFull = dragging == null
                  ? full
                  : math.max(_minList, math.min(dragging, room - _minDetail));
              final shown = dragging ?? full * _open.value;
              final gone = shown <= 0.5;
              return Stack(children: [
                Positioned.fill(
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      SizedBox(
                        width: shown,
                        // The list keeps its width while it slides away:
                        // no row is laid out again on every frame.
                        child: ClipRect(
                          child: OverflowBox(
                            alignment: Alignment.centerRight,
                            minWidth: listFull,
                            maxWidth: listFull,
                            child: Offstage(
                              offstage: gone,
                              child: TickerMode(
                                enabled: !gone,
                                child: ExcludeFocus(
                                  excluding: gone,
                                  // Above the bar, which the keyboard covers.
                                  child: ValueListenableBuilder<double>(
                                    valueListenable: widget.barHeight,
                                    builder: (context, bar, _) => Padding(
                                      padding: EdgeInsets.only(bottom: bar),
                                      child: _PagesInset(
                                          barHeight: widget.barHeight,
                                          child: widget.list),
                                    ),
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                      ),
                      _PaneDivider(shown: !gone),
                      Expanded(
                        // The whole height of the window, folded or not.
                        // Laid out at the width it will have once the list
                        // has moved, and clipped to what shows: its web view
                        // is not resized on every frame (no blank strip); a
                        // resize by the divider does resize it.
                        child: LayoutBuilder(builder: (context, box) {
                          final resizing =
                              dragging != null && !shell.listCollapsed.value;
                          final target = shell.listCollapsed.value
                              ? room
                              : room - full - 1;
                          final w = resizing ? box.maxWidth : target;
                          return ClipRect(
                            child: OverflowBox(
                              alignment: Alignment.centerLeft,
                              minWidth: w,
                              maxWidth: w,
                              child: _Pane(
                                  removeLeft: !gone, child: widget.detail),
                            ),
                          );
                        }),
                      ),
                    ],
                  ),
                ),
                // Flush at the bottom of the list pane, its width; its own
                // colour runs under the system navigation. No top: it is
                // as high as its buttons, never the pane's height.
                Positioned(
                  left: shown - listFull,
                  bottom: 0,
                  width: listFull,
                  child: Offstage(
                    offstage: gone,
                    child: TickerMode(
                      enabled: !gone,
                      child: ExcludeFocus(excluding: gone, child: widget.bar),
                    ),
                  ),
                ),
                _PaneHandle(
                  at: shown,
                  collapsed: shell.listCollapsed.value,
                  onTap: _toggle,
                  onDragStart: () => _dragStart(full),
                  onDragUpdate: (d) => _dragUpdate(d, room),
                  onDragEnd: (v) => _dragEnd(room, v),
                ),
              ]);
            },
          );
        },
      );
    });
  }
}

/// The divider's handle: a small tab on the line, half-way down, with a
/// chevron that says which way a tap folds the list. Along the whole line a
/// strip takes drags (to resize); the tab is a full touch target.
class _PaneHandle extends StatelessWidget {
  /// Where the divider is (the list pane's width now).
  final double at;
  final bool collapsed;
  final VoidCallback onTap;
  final VoidCallback onDragStart;
  final GestureDragUpdateCallback onDragUpdate;
  final ValueSetter<double> onDragEnd;

  const _PaneHandle({
    required this.at,
    required this.collapsed,
    required this.onTap,
    required this.onDragStart,
    required this.onDragUpdate,
    required this.onDragEnd,
  });

  static const _strip = 16.0;

  /// The width of the edge strip that opens a folded list.
  static const edgeStrip = 24.0;
  static const _tab = Size(24, 48);
  static const _target = Size(48, 64);

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    // Folded, the tab sticks out of the left edge.
    final x = math.max(at, _tab.width / 2);
    Widget drag(Widget child) => GestureDetector(
          behavior: HitTestBehavior.translucent,
          onHorizontalDragStart: (_) => onDragStart(),
          onHorizontalDragUpdate: onDragUpdate,
          onHorizontalDragEnd: (d) => onDragEnd(d.primaryVelocity ?? 0),
          onHorizontalDragCancel: () => onDragEnd(0),
          child: child,
        );
    return Positioned.fill(
      child: LayoutBuilder(builder: (context, box) {
        final middle = box.maxHeight / 2;
        return Stack(children: [
          if (!collapsed)
            Positioned(
              left: at - _strip / 2,
              top: 0,
              bottom: 0,
              width: _strip,
              child: drag(const SizedBox.expand()),
            ),
          // Folded: a strip along the window's left edge opens the list with
          // one drag that follows the finger. It starts beyond the system
          // gesture inset (Android's back swipe owns the very edge) and is
          // a Flutter widget above the pages' web view, so the web view's
          // own horizontal scrolling is not touched elsewhere.
          if (collapsed)
            Positioned(
              left: MediaQuery.systemGestureInsetsOf(context).left,
              top: 0,
              bottom: 0,
              width: edgeStrip,
              child: drag(const SizedBox.expand()),
            ),
          Positioned(
            left: x - _target.width / 2,
            top: middle - _target.height / 2,
            width: _target.width,
            height: _target.height,
            child: drag(Tooltip(
              message: collapsed ? 'Show list' : 'Hide list',
              child: Semantics(
                button: true,
                label: collapsed ? 'Show list' : 'Hide list',
                excludeSemantics: true,
                child: GestureDetector(
                  key: const Key('list-toggle'),
                  behavior: HitTestBehavior.opaque,
                  onTap: onTap,
                  child: Center(
                    child: Container(
                      width: _tab.width,
                      height: _tab.height,
                      decoration: BoxDecoration(
                        color: c.barSurface,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                            color:
                                Theme.of(context).colorScheme.outlineVariant),
                      ),
                      child: Icon(
                        collapsed ? Icons.chevron_right : Icons.chevron_left,
                        size: 18,
                        color: c.textSecondary,
                      ),
                    ),
                  ),
                ),
              ),
            )),
          ),
        ]);
      }),
    );
  }
}

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
    final shell = ShellScope.maybeOf(context);
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
            if (shell != null)
              ValueListenableBuilder<bool>(
                valueListenable: shell.listCollapsed,
                builder: (context, collapsed, _) => collapsed
                    ? Padding(
                        padding: const EdgeInsets.only(top: 8),
                        child: TextButton(
                          onPressed: () => shell.setListCollapsed(false),
                          child: const Text('Show list'),
                        ),
                      )
                    : const SizedBox.shrink(),
              ),
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
                  kind: shell.search.kind,
                  initialQuery: shell.search.query,
                ),
              ),
          ]);
        },
      );
}

/// A pane of the split layout: the system insets of the sides it does not
/// touch are not its business.
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
  final bool shown;

  const _PaneDivider({required this.shown});

  /// The theme's divider: a hairline that is quiet in light and dark.
  @override
  Widget build(BuildContext context) => ColoredBox(
      color: Theme.of(context).colorScheme.outlineVariant,
      child: SizedBox(width: shown ? 1 : 0));
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
