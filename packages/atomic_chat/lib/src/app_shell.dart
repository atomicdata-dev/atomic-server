import 'dart:async';
import 'dart:math' as math;

import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt, HoldFan;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/physics.dart' show SpringDescription, SpringSimulation;
import 'package:flutter/scheduler.dart';
import 'package:flutter/services.dart'
    show
        HapticFeedback,
        HardwareKeyboard,
        KeyEvent,
        KeyDownEvent,
        LogicalKeyboardKey;
import 'package:shared_preferences/shared_preferences.dart';

import 'covered_insets_freeze.dart';
import 'app_bottom_bar.dart';
import 'models.dart';
import 'assistant_api.dart';
import 'search_screen.dart';
import 'new_document_sheet.dart' show warmDriveVisits;
import 'native_views.dart';
import 'warm_resource_web_view.dart';
import 'slide_back_route.dart';
import 'home_sections.dart' show HomeSection, HomeSectionEntry;
import 'list_and_field.dart' show readableHorizontalPadding;

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

/// The home's activity feed as the home read it, with the home's own row
/// for an entry (its icon, what a tap opens).
typedef HomeFeed = ({
  List<ActivityEntry> entries,
  Widget Function(ActivityEntry) row,
  // "Show mine": the person's own changes too.
  bool mine,
  ValueChanged<bool> onMine,
});

/// The activity feed's "Show mine": also the person's own changes.
class ShowMineChip extends StatelessWidget {
  final bool value;
  final ValueChanged<bool> onChanged;

  const ShowMineChip({super.key, required this.value, required this.onChanged});

  @override
  Widget build(BuildContext context) => FilterChip(
        key: const Key('show-mine'),
        label: const Text('Show mine'),
        selected: value,
        onSelected: onChanged,
        visualDensity: VisualDensity.compact,
      );
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

  /// The home sections the Home button's hold menu offers: every section, in
  /// the home's saved order, those hidden from the home and those with
  /// nothing to list included (the home publishes them).
  final ValueNotifier<List<HomeSectionEntry>> homeSections =
      ValueNotifier(const []);

  /// The last section picked from the Home button's menu; the home opens its
  /// full list.
  final ValueNotifier<({HomeSection section, int n})?> sectionRequest =
      ValueNotifier(null);

  /// Home, with [section] unfolded and its full list open.
  void openHomeSection(HomeSection section) {
    if (split) {
      showList(ShellPage.home);
    } else {
      goHome();
    }
    sectionRequest.value =
        (section: section, n: (sectionRequest.value?.n ?? 0) + 1);
  }

  /// The search palette is open over the window (split layout).
  final ValueNotifier<bool> searching = ValueNotifier(false);

  /// The home's activity feed, which the detail pane shows while nothing is
  /// open (split layout); the home publishes it, null until it has read it.
  final ValueNotifier<HomeFeed?> activity = ValueNotifier(null);

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

  /// What runs when a page opened by [openDetail] is left (popped, or
  /// replaced by the next one).
  final Map<Route<dynamic>, VoidCallback> _onLeave = {};

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

  /// How long to wait before loading the identity again when its picture has
  /// not arrived yet (one entry per retry; the sync may still be fetching
  /// the file).
  List<Duration> identityRetries = const [
    Duration(seconds: 5),
    Duration(seconds: 20),
    Duration(seconds: 60),
  ];
  int _identityRetry = 0;
  Timer? _identityTimer;

  /// Loads the identity again (after the profile was edited, on resume).
  Future<void> refreshIdentity() async {
    final load = identityLoader;
    if (load == null) return;
    final n = ++_identityLoads;
    try {
      var who = await load();
      // The latest request wins.
      if (_disposed || n != _identityLoads) return;
      if (who == null) return;
      final before = identity.value;
      // A load that could not read the picture does not take away the one
      // already shown.
      if (who.pendingImage &&
          before != null &&
          (before.imageBytes != null || before.imageUrl != null) &&
          who.imageBytes == null &&
          who.imageUrl == null) {
        who = ProfileIdentity(
            name: who.name,
            imageUrl: before.imageUrl,
            imageBytes: before.imageBytes,
            emoji: who.emoji,
            pendingImage: true);
      }
      identity.value = who;
      _identityTimer?.cancel();
      if (!who.pendingImage) {
        _identityRetry = 0;
      } else if (_identityRetry < identityRetries.length) {
        _identityTimer =
            Timer(identityRetries[_identityRetry++], refreshIdentity);
      }
    } catch (e) {
      // The last one stays.
      debugPrint('Profile identity not loaded: $e');
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
  ///
  /// [onLeave] runs once the page is left: a list notes the visit then, so
  /// it does not reorder under the finger that just opened the row.
  Future<T?> openDetail<T>(WidgetBuilder builder,
      {String? subject, VoidCallback? onLeave}) async {
    final navigator = navigatorKey.currentState;
    if (navigator == null) return null;
    if (split && subject != null && _top != null && _details[_top] == subject) {
      return null;
    }
    // Next to the list the pane just shows it: no slide to wait for.
    final route = SlideBackRoute<T>(builder: builder, instant: split);
    if (subject != null) _details[route] = subject;
    if (onLeave != null) _onLeave[route] = onLeave;
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
  Future<T?> openPage<T>(String kind, WidgetBuilder builder) => open<T>(
      kind,
      (settings) => SlideBackRoute<T>(
          builder: builder, settings: settings, instant: split));

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
    _onLeave.remove(route)?.call();
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
    _identityTimer?.cancel();
    drive.dispose();
    identity.dispose();
    list.dispose();
    activity.dispose();
    searching.dispose();
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
    {String? subject, VoidCallback? onLeave}) {
  final shell = ShellScope.maybeOf(context);
  if (shell != null && shell.navigatorKey.currentState != null) {
    return shell.openDetail<T>(builder, subject: subject, onLeave: onLeave);
  }
  final pushed =
      Navigator.of(context).push(SlideBackRoute<T>(builder: builder));
  if (onLeave != null) pushed.whenComplete(onLeave);
  return pushed;
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
    // Not a MaterialPageRoute: the home never animates itself, and the
    // platform's page transition (predictive back on Android) applied to it
    // as the page under a closing one left its bottom corners rounded and
    // black after a swipe back from search.
    onGenerateRoute: (_) => PageRouteBuilder<void>(
      settings: const RouteSettings(name: ShellPage.home),
      transitionDuration: Duration.zero,
      reverseTransitionDuration: Duration.zero,
      pageBuilder: (_, __, ___) =>
          CoveredInsetsFreeze(child: _HomeSlot(home: _home)),
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
    warmDriveVisits();
    _shell.identityLoader = widget.api.ownIdentity;
    _shell.refreshIdentity();
    WidgetsBinding.instance.addObserver(this);
    HardwareKeyboard.instance.addHandler(_onKey);
  }

  /// Cmd+B (macOS) or Ctrl+B (Linux, Windows) folds or unfolds the sidebar,
  /// whatever has the focus. Desktop and the split layout only.
  bool _onKey(KeyEvent event) {
    if (event is! KeyDownEvent ||
        event.logicalKey != LogicalKeyboardKey.keyB ||
        !_PaneHandle.isDesktop ||
        !_shell.split) {
      return false;
    }
    final kb = HardwareKeyboard.instance;
    final mac = defaultTargetPlatform == TargetPlatform.macOS;
    if (!(mac ? kb.isMetaPressed : kb.isControlPressed) ||
        kb.isShiftPressed ||
        kb.isAltPressed) {
      return false;
    }
    _shell.setListCollapsed(!_shell.listCollapsed.value);
    return true;
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
    HardwareKeyboard.instance.removeHandler(_onKey);
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

/// [width] (plus the 1 dp divider after it) on a whole number of physical
/// pixels. The detail pane's web view is a texture: placed at a fraction of a
/// pixel (400 dp + 1 dp is 852.125 px at 2.125) it is resampled, and its
/// text and lines turn blurry. A zero or hidden width stays as it is.
double snapPaneWidth(double width, double devicePixelRatio) {
  if (width <= 0.5 || devicePixelRatio <= 0) return width;
  return ((width + 1) * devicePixelRatio).round() / devicePixelRatio - 1;
}

/// Room for the bar's six 48 dp slots and its padding.
const _minList = 304.0;
const _maxDragged = 520.0;
const _minDetail = 280.0;

/// How far past its bounds the list pane can be pulled, however far the
/// finger goes: the pull gets harder the further it goes (a tanh band, 1:1
/// at the bound), and the pane springs back on release.
const listOvershootLimit = 48.0;

/// The spring that brings the list pane back to its bound: a little under
/// critical damping (a hair of overshoot), settled in about 300 ms.
final listSpring =
    SpringDescription.withDampingRatio(mass: 1, stiffness: 260, ratio: 0.85);

double _tanh(double x) {
  final e = math.exp(2 * x.clamp(-20.0, 20.0));
  return (e - 1) / (e + 1);
}

/// The width shown for a finger at [raw]: the same inside [lo]..[hi], and
/// outside it never more than [listOvershootLimit] past the bound (the
/// divider uses 0 for [lo]: closing is never resisted).
double listRubberBand(double raw, double lo, double hi) {
  const l = listOvershootLimit;
  if (raw > hi) return hi + l * _tanh((raw - hi) / l);
  if (raw < lo) return lo - l * _tanh((lo - raw) / l);
  return raw;
}

/// The finger position that shows [shown] (the inverse of [listRubberBand]).
double listRubberBandInverse(double shown, double lo, double hi) {
  const l = listOvershootLimit;
  double atanh(double y) {
    final c = y.clamp(-0.999999, 0.999999);
    return 0.5 * math.log((1 + c) / (1 - c));
  }

  if (shown > hi) return hi + l * atanh((shown - hi) / l);
  if (shown < lo) return lo - l * atanh((lo - shown) / l);
  return shown;
}

/// How fast the shown width follows the finger at [raw] (1 inside the range).
double listRubberBandSlope(double raw, double lo, double hi) {
  if (raw <= hi && raw >= lo) return 1;
  final t = _tanh((raw > hi ? raw - hi : lo - raw) / listOvershootLimit);
  return 1 - t * t;
}

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
    with TickerProviderStateMixin {
  late final AnimationController _open = AnimationController(
    vsync: this,
    duration: listFoldDuration,
    value: widget.shell.listCollapsed.value ? 0 : 1,
  );

  /// Drives the width back to its bound after a drag went past it.
  late final AnimationController _spring = AnimationController.unbounded(
    vsync: this,
  );

  /// The width shown while the divider is being dragged, or springing back.
  double? _dragging;

  /// Where the finger would have the divider, without the resistance.
  double _raw = 0;
  bool _springing = false;
  bool _atBound = false;
  bool _foldArmed = false;

  @override
  void initState() {
    super.initState();
    widget.shell.listCollapsed.addListener(_fold);
    _spring.addListener(() {
      if (_springing) setState(() => _dragging = _spring.value);
    });
    _spring.addStatusListener((status) {
      if (status == AnimationStatus.completed && _springing) {
        setState(() {
          _springing = false;
          _dragging = null;
        });
      }
    });
  }

  @override
  void dispose() {
    widget.shell.listCollapsed.removeListener(_fold);
    _open.dispose();
    _spring.dispose();
    super.dispose();
  }

  void _fold() {
    final collapsed = widget.shell.listCollapsed.value;
    _open.animateTo(collapsed ? 0 : 1, curve: Curves.easeOutCubic);
  }

  void _toggle() =>
      widget.shell.setListCollapsed(!widget.shell.listCollapsed.value);

  double _hi(double room) =>
      math.max(_minList, math.min(_maxDragged, room - _minDetail));

  /// Narrower than the minimum there is no resistance: the pane follows the
  /// finger all the way to nothing, so it can be swiped fully closed.
  double _lo() => 0;

  void _dragStart(double full, double room) {
    final collapsed = widget.shell.listCollapsed.value;
    if (_springing) {
      // Caught on its way back: carry on from where it is shown.
      _springing = false;
      _spring.stop();
      final shown = _dragging ?? full;
      _raw = listRubberBandInverse(shown, _lo(), _hi(room));
    } else {
      _raw = collapsed ? 0 : full;
    }
    _atBound = false;
    _foldArmed = false;
    setState(() => _dragging = listRubberBand(_raw, _lo(), _hi(room)));
  }

  void _dragUpdate(DragUpdateDetails d, double room) {
    if (_dragging == null || _springing) return;
    _raw = math.max(0.0, _raw + d.delta.dx);
    final lo = _lo(), hi = _hi(room);
    final out = _raw > hi || _raw < lo;
    if (out && !_atBound) HapticFeedback.selectionClick();
    _atBound = out;
    if (!widget.shell.listCollapsed.value) {
      final armed = _raw < _minList * 0.6;
      if (armed && !_foldArmed) HapticFeedback.selectionClick();
      _foldArmed = armed;
    }
    setState(() => _dragging = listRubberBand(_raw, lo, hi));
  }

  /// A fling faster than this (dp/s) opens or folds the list whatever the
  /// distance.
  static const _fling = 300.0;

  /// Runs the width from [from] to [to] with a spring, [velocity] dp/s in.
  void _springBack(double from, double to, double velocity) {
    _springing = false;
    _spring.stop();
    _spring.value = from;
    _springing = true;
    _spring.animateWith(SpringSimulation(listSpring, from, to, velocity));
  }

  void _dragEnd(double room, double velocity) {
    final w = _dragging;
    if (w == null || _springing) return;
    final shell = widget.shell;
    final full = listPaneWidth(room, dragged: shell.listWidth.value);
    final lo = _lo(), hi = _hi(room);
    // The finger's speed as the shown width moves (the band slows it).
    final slope = listRubberBandSlope(_raw, lo, hi);
    if (shell.listCollapsed.value) {
      // Opening from the edge: follows the finger, then settles open (past a
      // third of the way, or flung right) or back.
      _open.value = (w / full).clamp(0.0, 1.0);
      if (velocity > _fling || (velocity > -_fling && w > full / 3)) {
        shell.setListCollapsed(false);
        if (w > full + 0.5) {
          _open.value = 1;
          _springBack(w, full, velocity * slope);
          return;
        }
        setState(() => _dragging = null);
        _open.animateTo(1, curve: Curves.easeOutCubic);
      } else {
        setState(() => _dragging = null);
        _open.animateTo(0, curve: Curves.easeOutCubic);
      }
      return;
    }
    if (velocity < -_fling && w < full) {
      // Flung left: fold from where the finger left it.
      setState(() => _dragging = null);
      _open.value = (w / full).clamp(0.0, 1.0);
      shell.setListCollapsed(true);
      return;
    }
    if (_raw < _minList * 0.6) {
      // From where the finger left it.
      setState(() => _dragging = null);
      _open.value = (w / full).clamp(0.0, 1.0);
      shell.setListCollapsed(true);
      return;
    }
    // Only the settled width is kept, never the overshoot.
    final settled = listPaneWidth(room, dragged: w);
    shell.setListWidth(settled);
    _open.value = 1;
    shell.setListCollapsed(false);
    if ((w - settled).abs() > 0.5) {
      _springBack(w, settled, velocity * slope);
    } else {
      setState(() => _dragging = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    final shell = widget.shell;
    return LayoutBuilder(builder: (context, box) {
      final room = box.maxWidth;
      final dpr = MediaQuery.devicePixelRatioOf(context);
      return ValueListenableBuilder<double?>(
        valueListenable: shell.listWidth,
        builder: (context, dragged, _) {
          final full =
              snapPaneWidth(listPaneWidth(room, dragged: dragged), dpr);
          return AnimatedBuilder(
            animation: _open,
            builder: (context, _) {
              final dragging = _dragging;
              final listFull = dragging == null
                  ? full
                  : math.max(_minList, math.min(dragging, room - _minDetail));
              final shown = snapPaneWidth(dragging ?? full * _open.value, dpr);
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
                      _PaneDivider(shown: !gone, active: dragging != null),
                      Expanded(
                        child: Column(children: [
                          // Folded on a desktop: the bar is folded away with
                          // the list, so the pages get a slim top bar with
                          // the button that brings it back.
                          shell.listCollapsed.value && _PaneHandle.isDesktop
                              ? _ReopenBar(onTap: _toggle)
                              : const SizedBox.shrink(),
                          Expanded(
                              child:
                                  _detail(shell, room, full, dragging, gone)),
                        ]),
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
                  dragging: dragging != null,
                  collapsed: shell.listCollapsed.value,
                  onTap: _toggle,
                  onDragStart: () => _dragStart(full, room),
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

  Widget _detail(ShellController shell, double room, double full,
      double? dragging, bool gone) {
    // The whole height of the window, folded or not. Laid out at the width it
    // will have once the list has moved, and clipped to what shows: its web
    // view is not resized on every frame (no blank strip); a resize by the
    // divider does resize it.
    return LayoutBuilder(builder: (context, box) {
      final resizing = dragging != null && !shell.listCollapsed.value;
      final target = shell.listCollapsed.value ? room : room - full - 1;
      final w = resizing ? box.maxWidth : target;
      return ClipRect(
        child: OverflowBox(
          alignment: Alignment.centerLeft,
          minWidth: w,
          maxWidth: w,
          child: _Pane(removeLeft: !gone, child: widget.detail),
        ),
      );
    });
  }
}

/// The divider's handle: a small tab on the line, half-way down, with a
/// chevron that says which way a tap folds the list. Along the whole line a
/// strip takes drags (to resize); the tab is a full touch target.
class _PaneHandle extends StatefulWidget {
  /// Where the divider is (the list pane's width now).
  final double at;

  /// The divider is being dragged.
  final bool dragging;
  final bool collapsed;
  final VoidCallback onTap;
  final VoidCallback onDragStart;
  final GestureDragUpdateCallback onDragUpdate;
  final ValueSetter<double> onDragEnd;

  const _PaneHandle({
    required this.at,
    required this.dragging,
    required this.collapsed,
    required this.onTap,
    required this.onDragStart,
    required this.onDragUpdate,
    required this.onDragEnd,
  });

  static const _strip = 16.0;

  /// A mouse platform: the line is the handle, there is no tab.
  static bool get isDesktop => switch (defaultTargetPlatform) {
        TargetPlatform.macOS ||
        TargetPlatform.linux ||
        TargetPlatform.windows =>
          true,
        _ => false,
      };

  /// The transparent resize strip on the line, and the one at the window's
  /// edge that opens a folded list.
  static const desktopStrip = 8.0;
  static const desktopEdge = 10.0;

  /// The width of the edge strip that opens a folded list.
  static const edgeStrip = 24.0;
  static const _tab = Size(24, 48);
  static const _target = Size(48, 64);

  /// How visible the tab is at rest, and on hover or drag.
  static const restOpacity = 0.15;
  static const activeOpacity = 0.4;

  @override
  State<_PaneHandle> createState() => _PaneHandleState();
}

class _PaneHandleState extends State<_PaneHandle> {
  bool _hover = false;
  bool _edgeHover = false;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final at = widget.at;
    final collapsed = widget.collapsed;
    final onTap = widget.onTap;
    final onDragStart = widget.onDragStart;
    final onDragUpdate = widget.onDragUpdate;
    final onDragEnd = widget.onDragEnd;
    const strip = _PaneHandle._strip;
    const tab = _PaneHandle._tab;
    const target = _PaneHandle._target;
    final x = at;
    final desktop = _PaneHandle.isDesktop;
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
          // Desktop (a mouse): the line itself is the handle along its whole
          // height, an 8 dp transparent strip centred on it. It lights up on
          // hover, takes the accent while dragged, and a double click folds
          // or unfolds the list. No tab: that is for touch.
          if (!collapsed && desktop) ...[
            Positioned(
              left: at,
              top: 0,
              bottom: 0,
              width: 1,
              child: IgnorePointer(
                child: AnimatedContainer(
                  key: const Key('pane-line-highlight'),
                  duration: const Duration(milliseconds: 120),
                  color: widget.dragging
                      ? c.main.withValues(alpha: 0.6)
                      : (_hover
                          ? (c.bgBody.computeLuminance() < 0.5
                                  ? Colors.white
                                  : Colors.black)
                              .withValues(alpha: 0.2)
                          : Colors.transparent),
                ),
              ),
            ),
            Positioned(
              left: at + 0.5 - _PaneHandle.desktopStrip / 2,
              top: 0,
              bottom: 0,
              width: _PaneHandle.desktopStrip,
              child: MouseRegion(
                key: const Key('pane-resize-strip'),
                cursor: SystemMouseCursors.resizeColumn,
                onEnter: (_) => setState(() => _hover = true),
                onExit: (_) => setState(() => _hover = false),
                child: GestureDetector(
                  behavior: HitTestBehavior.translucent,
                  onDoubleTap: onTap,
                  onHorizontalDragStart: (_) => onDragStart(),
                  onHorizontalDragUpdate: onDragUpdate,
                  onHorizontalDragEnd: (d) => onDragEnd(d.primaryVelocity ?? 0),
                  onHorizontalDragCancel: () => onDragEnd(0),
                  child: const SizedBox.expand(),
                ),
              ),
            ),
          ],
          if (!collapsed && !desktop)
            Positioned(
              left: at - strip / 2,
              top: 0,
              bottom: 0,
              width: strip,
              child: MouseRegion(
                onEnter: (_) => setState(() => _hover = true),
                onExit: (_) => setState(() => _hover = false),
                child: drag(const SizedBox.expand()),
              ),
            ),
          // Folded: a strip along the window's left edge opens the list with
          // one drag that follows the finger. It starts beyond the system
          // gesture inset (Android's back swipe owns the very edge) and is
          // a Flutter widget above the pages' web view, so the web view's
          // own horizontal scrolling is not touched elsewhere.
          // Opaque: the web view under it (which claims a touch at once)
          // never sees the swipe.
          if (collapsed && desktop)
            Positioned(
              left: 0,
              top: 0,
              bottom: 0,
              width: _PaneHandle.desktopEdge,
              child: MouseRegion(
                key: const Key('pane-reveal-strip'),
                cursor: SystemMouseCursors.click,
                onEnter: (_) => setState(() => _edgeHover = true),
                onExit: (_) => setState(() => _edgeHover = false),
                child: GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: onTap,
                  onHorizontalDragStart: (_) => onDragStart(),
                  onHorizontalDragUpdate: onDragUpdate,
                  onHorizontalDragEnd: (d) => onDragEnd(d.primaryVelocity ?? 0),
                  onHorizontalDragCancel: () => onDragEnd(0),
                  child: AnimatedContainer(
                    key: const Key('pane-reveal-highlight'),
                    duration: const Duration(milliseconds: 120),
                    color: _edgeHover
                        ? c.main.withValues(alpha: 0.35)
                        : Colors.transparent,
                  ),
                ),
              ),
            ),
          if (collapsed && !desktop)
            Positioned(
              left: MediaQuery.systemGestureInsetsOf(context).left,
              top: 0,
              bottom: 0,
              width: _PaneHandle.edgeStrip,
              child: GestureDetector(
                behavior: HitTestBehavior.opaque,
                onHorizontalDragStart: (_) => onDragStart(),
                onHorizontalDragUpdate: onDragUpdate,
                onHorizontalDragEnd: (d) => onDragEnd(d.primaryVelocity ?? 0),
                onHorizontalDragCancel: () => onDragEnd(0),
              ),
            ),
          // Folded: a button at the bottom left, where the bar was, opens it.
          if (collapsed && !desktop)
            Positioned(
              left: 8 + MediaQuery.paddingOf(context).left,
              bottom: 8 + MediaQuery.viewPaddingOf(context).bottom,
              child: Material(
                color: c.barSurface,
                elevation: 2,
                shape: const CircleBorder(),
                child: IconButton(
                  key: const Key('list-toggle'),
                  tooltip: 'Show list',
                  onPressed: onTap,
                  icon: const Icon(Icons.menu),
                ),
              ),
            ),
          if (!collapsed && !desktop)
            Positioned(
              left: x - target.width / 2,
              top: middle - target.height / 2,
              width: target.width,
              height: target.height,
              child: MouseRegion(
                  onEnter: (_) => setState(() => _hover = true),
                  onExit: (_) => setState(() => _hover = false),
                  child: drag(Tooltip(
                    message: 'Hide list',
                    child: Semantics(
                      button: true,
                      label: 'Hide list',
                      excludeSemantics: true,
                      child: GestureDetector(
                        key: const Key('list-toggle'),
                        behavior: HitTestBehavior.opaque,
                        onTap: onTap,
                        child: Center(
                          child: AnimatedOpacity(
                            key: const Key('pane-grabber'),
                            duration: const Duration(milliseconds: 180),
                            opacity: _hover || widget.dragging
                                ? _PaneHandle.activeOpacity
                                : _PaneHandle.restOpacity,
                            child: Container(
                              width: tab.width,
                              height: tab.height,
                              decoration: BoxDecoration(
                                color: c.barSurface,
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                    color: _PaneDivider.colorFor(c.bgBody,
                                        active: false)),
                              ),
                              child: Icon(
                                Icons.chevron_left,
                                size: 18,
                                color: c.textSecondary,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ))),
            ),
        ]);
      }),
    );
  }
}

/// Folded on a desktop, the list pane's bottom bar is gone with it: a slim
/// bar on top of the pages with the button that shows the sidebar again.
class _ReopenBar extends StatelessWidget {
  final VoidCallback onTap;

  const _ReopenBar({required this.onTap});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final mac = defaultTargetPlatform == TargetPlatform.macOS;
    return Material(
      color: c.bgBody,
      child: Align(
        alignment: Alignment.centerLeft,
        heightFactor: 1,
        child: Padding(
          // 8 dp in. The window's own title bar holds the traffic lights
          // (the macOS runner does not hide it), so nothing to clear.
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 4),
          child: IconButton(
            key: const Key('reopen-sidebar'),
            tooltip: mac ? 'Show sidebar (\u2318B)' : 'Show sidebar (Ctrl+B)',
            onPressed: onTap,
            mouseCursor: SystemMouseCursors.click,
            iconSize: 18,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints.tightFor(width: 28, height: 28),
            icon: const Icon(Icons.menu),
          ),
        ),
      ),
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

/// The detail pane before anything is opened: the home's activity feed,
/// big, in a readable column.
class _NothingOpen extends StatelessWidget {
  const _NothingOpen();

  static final _noFeed = ValueNotifier<HomeFeed?>(null);

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final shell = ShellScope.maybeOf(context);
    return Scaffold(
      key: const Key('nothing-open'),
      backgroundColor: c.bgBody,
      body: SafeArea(
        bottom: false,
        child: ValueListenableBuilder<HomeFeed?>(
          valueListenable: shell?.activity ?? _noFeed,
          // The list spans the pane (its scrollbar at the edge); it centres
          // its own content.
          builder: (context, feed, _) => LayoutBuilder(
            builder: (context, box) => ListView(
              key: const Key('home-activity'),
              padding: readableHorizontalPadding(box.maxWidth, gutter: 8)
                  .copyWith(
                      top: 24,
                      bottom: 24 + MediaQuery.paddingOf(context).bottom),
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  child: Row(children: [
                    Expanded(
                      child: Text('Activity',
                          style: Theme.of(context)
                              .textTheme
                              .headlineSmall
                              ?.copyWith(
                                  color: c.textPrimary,
                                  fontWeight: FontWeight.w600)),
                    ),
                    if (feed != null)
                      ShowMineChip(value: feed.mine, onChanged: feed.onMine),
                  ]),
                ),
                if (feed == null)
                  const Padding(
                    padding: EdgeInsets.all(32),
                    child: Center(child: CircularProgressIndicator()),
                  )
                else if (feed.entries.isEmpty)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                    child: Text(
                        feed.mine
                            ? 'Nothing yet: what you and others change in '
                                'your drives shows up here.'
                            : 'Nothing yet: what others change in your '
                                'drives shows up here. "Show mine" adds '
                                'your own changes.',
                        style: TextStyle(color: c.textSecondary)),
                  )
                else
                  for (final a in feed.entries) feed.row(a),
              ],
            ),
          ),
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

  /// Being dragged: the line brightens a little as feedback.
  final bool active;

  const _PaneDivider({required this.shown, this.active = false});

  /// A 1 dp hairline in the border token, barely there at rest (light 8%,
  /// dark 10%) and 18% while dragged.
  static Color colorFor(Color bgBody, {required bool active}) {
    final dark = bgBody.computeLuminance() < 0.5;
    return (dark ? Colors.white : Colors.black)
        .withValues(alpha: active ? 0.18 : (dark ? 0.10 : 0.08));
  }

  @override
  Widget build(BuildContext context) {
    final page = context.appColors.bgBody;
    // The line is a translucent ink: drawn over nothing it shows what is
    // behind the window (black), a solid black line in light mode. So it
    // lies on an opaque strip in the page colour, and only the ink is quiet.
    return ColoredBox(
      color: page,
      child: ColoredBox(
          key: const Key('pane-divider'),
          color: colorFor(page, active: active),
          child: SizedBox(width: shown ? 1 : 0)),
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
