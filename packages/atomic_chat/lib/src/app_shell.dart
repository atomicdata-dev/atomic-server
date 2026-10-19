import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/scheduler.dart';

import 'covered_insets_freeze.dart';
import 'app_bottom_bar.dart';
import 'models.dart';
import 'assistant_api.dart';
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

/// What the static bottom bar needs to know about the pages above it. The
/// shell owns one; pages find it through [ShellScope].
/// Opens a page's menu; [anchor] is the bar button that asked, in global
/// coordinates, so the menu opens at that button.
typedef ShellMenu = void Function(Rect anchor);

class ShellController extends ChangeNotifier {
  final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

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

  /// Whether a page of [kind] is anywhere in the stack.
  bool hasPage(String kind) => _stack.any((r) => kindOf(r) == kind);

  /// [route] is a page of [kind] from now on (null: of none).
  void setKind(Route<dynamic> route, String? kind) {
    if (_kinds.containsKey(route) && _kinds[route] == kind) return;
    _kinds[route] = kind;
    if (identical(route, _top)) _changed();
  }

  /// A push from the bar happened a moment ago: a second tap is ignored.
  Timer? _settling;

  /// Opens the page of [kind] the bar asks for, at most once: nothing
  /// happens when it is on top already or a push is under way (a double
  /// tap), and when it is further down the stack the pages above it are
  /// popped instead of a second one pushed. Answers what the pushed page pops
  /// with; null when nothing was pushed.
  Future<T?> open<T>(
      String kind, Route<T> Function(RouteSettings settings) route) async {
    final navigator = navigatorKey.currentState;
    if (navigator == null || topKind == kind || _settling != null) return null;
    if (hasPage(kind)) {
      navigator.popUntil((r) => kindOf(r) == kind);
      return null;
    }
    _settling =
        Timer(const Duration(milliseconds: 300), () => _settling = null);
    return navigator.push(route(RouteSettings(name: kind)));
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
  }

  void _setTop(Route<dynamic>? route) {
    if (identical(route, _top)) return;
    _top = route;
    _changed();
  }

  // Navigator observers run while the navigator is building at times (its
  // first route), and a listener must not rebuild then.
  void _changed() {
    if (_disposed) return;
    if (SchedulerBinding.instance.schedulerPhase ==
        SchedulerPhase.persistentCallbacks) {
      SchedulerBinding.instance.addPostFrameCallback((_) {
        if (!_disposed) notifyListeners();
      });
    } else {
      notifyListeners();
    }
  }

  bool _disposed = false;

  @override
  void dispose() {
    _disposed = true;
    _settling?.cancel();
    drive.dispose();
    super.dispose();
  }
}

/// Finds the [ShellController] of the shell a page is in, if any.
class ShellScope extends InheritedWidget {
  final ShellController controller;

  const ShellScope({super.key, required this.controller, required super.child});

  static ShellController? maybeOf(BuildContext context) =>
      context.getInheritedWidgetOfExactType<ShellScope>()?.controller;

  @override
  bool updateShouldNotify(ShellScope old) => controller != old.controller;
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

  /// One instance for the life of the shell: the keyboard animation rebuilds
  /// the tiny widgets around it, never the pages.
  late final Widget _navigator = Navigator(
    key: _shell.navigatorKey,
    observers: [_observer],
    onGenerateRoute: (_) => MaterialPageRoute<void>(
      settings: const RouteSettings(name: ShellPage.home),
      builder: (_) => CoveredInsetsFreeze(child: widget.home),
    ),
  );

  final ValueNotifier<double> _barHeight = ValueNotifier(0);

  late final Widget _bar =
      _FrozenBottomPadding(child: AppBottomBar(api: widget.api, shell: _shell));

  @override
  void initState() {
    super.initState();
    // The shell exists once the person is in and the host's store is open:
    // load the next resource's page now, while they look at the home.
    _shell.warm =
        (widget.warmPool ?? WarmResourceWebView.forPlatform)(widget.api)
          ?..warmUp();
  }

  @override
  void dispose() {
    _shell.warm?.dispose();
    _shell.dispose();
    _barHeight.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ShellScope(
      controller: _shell,
      // Android back pops the pages first and leaves the app on the home.
      child: NavigatorPopHandler(
        onPopWithResult: (_) => _shell.navigatorKey.currentState?.maybePop(),
        child: Column(children: [
          // The bar stays laid out at full height; the keyboard covers it and
          // the pages get the keyboard minus the bar's height.
          Expanded(
              child: _PagesInset(barHeight: _barHeight, child: _navigator)),
          _MeasureHeight(height: _barHeight, child: _bar),
        ]),
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
