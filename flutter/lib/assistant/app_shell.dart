import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';

import '../widgets/covered_insets_freeze.dart';
import 'app_bottom_bar.dart';
import '../atomic/atomic_client.dart';
import 'assistant_api.dart';

/// What the static bottom bar needs to know about the pages above it. The
/// shell owns one; pages find it through [ShellScope].
class ShellController extends ChangeNotifier {
  final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

  /// The drive search looks in; the home updates it.
  final ValueNotifier<String> drive;

  /// Opens the user's page; the home sets it (it handles sign-out). Without
  /// one the bar opens the sync screen.
  VoidCallback? onUser;

  ShellController({String drive = ''}) : drive = ValueNotifier(drive);

  /// What search last knew (drives and recently opened), so it can paint the
  /// list on its first frame and refresh behind it.
  SearchCache? searchCache;

  final Map<Route<dynamic>, VoidCallback> _menus = {};
  Route<dynamic>? _top;

  /// The page route that is on top of the shell's navigator.
  Route<dynamic>? get top => _top;

  /// The menu action of the page on top, if that page has one.
  VoidCallback? get topMenu => _top == null ? null : _menus[_top];

  /// A page with a resource menu registers it under its own route. It only
  /// counts while that route is the top one.
  void registerMenu(Route<dynamic> route, VoidCallback onMore) {
    _menus[route] = onMore;
    _changed();
  }

  void unregisterMenu(Route<dynamic> route) {
    if (_menus.remove(route) != null) _changed();
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
    if (route is PageRoute) shell._setTop(route);
  }

  @override
  void didPop(Route<dynamic> route, Route<dynamic>? previousRoute) {
    if (route is PageRoute && previousRoute is PageRoute) {
      shell._setTop(previousRoute);
    }
  }

  @override
  void didRemove(Route<dynamic> route, Route<dynamic>? previousRoute) {
    if (identical(route, shell.top) && previousRoute is PageRoute) {
      shell._setTop(previousRoute);
    }
  }

  @override
  void didReplace({Route<dynamic>? newRoute, Route<dynamic>? oldRoute}) {
    if (newRoute is PageRoute) shell._setTop(newRoute);
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

  const AppShell({
    super.key,
    this.api = const AssistantApi(),
    required this.drive,
    required this.home,
  });

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  late final ShellController _shell = ShellController(drive: widget.drive);
  late final _TopObserver _observer = _TopObserver(_shell);

  /// One instance for the life of the shell: the keyboard animation rebuilds
  /// the tiny widgets around it, never the pages.
  late final Widget _navigator = Navigator(
    key: _shell.navigatorKey,
    observers: [_observer],
    onGenerateRoute: (_) => MaterialPageRoute<void>(
      builder: (_) => CoveredInsetsFreeze(child: widget.home),
    ),
  );

  late final Widget _bar = AppBottomBar(api: widget.api, shell: _shell);

  @override
  void dispose() {
    _shell.dispose();
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
          // The bar below takes the system inset; the pages must not reserve
          // it a second time.
          Expanded(child: _PagesInset(child: _navigator)),
          _BarSlot(child: _bar),
        ]),
      ),
    );
  }
}

/// Removes the bottom system inset from the pages. It follows MediaQuery, so
/// it is kept this small; its child is stable.
class _PagesInset extends StatelessWidget {
  final Widget child;

  const _PagesInset({required this.child});

  @override
  Widget build(BuildContext context) => MediaQuery.removePadding(
      context: context, removeBottom: true, child: child);
}

/// The keyboard overlays the screen and every page's Scaffold shrinks its body
/// by the full keyboard height. With the bar still below the pages they would
/// shrink by the bar's height too much (a gap above the keyboard). So the bar
/// steps aside, at once and without animating, while the keyboard is open: the
/// page region then ends at the screen bottom and its insets are exact, and
/// only the keyboard animates the layout. Only this widget reads the insets.
class _BarSlot extends StatefulWidget {
  final Widget child;

  const _BarSlot({required this.child});

  @override
  State<_BarSlot> createState() => _BarSlotState();
}

class _BarSlotState extends State<_BarSlot>
    with SingleTickerProviderStateMixin {
  /// 0 = hidden (keyboard open), 1 = shown. Hiding is at once; coming back
  /// grows and fades in, so the bar does not pop up when the keyboard is gone.
  late final AnimationController _shown = AnimationController(
      vsync: this, duration: const Duration(milliseconds: 220))
    ..value = 1;

  @override
  void dispose() {
    _shown.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final keyboardOpen = MediaQuery.viewInsetsOf(context).bottom > 0;
    if (keyboardOpen) {
      _shown.value = 0;
    } else if (_shown.value == 0 && !_shown.isAnimating) {
      _shown.forward();
    }
    return AnimatedBuilder(
      animation: _shown,
      child: widget.child,
      builder: (context, child) {
        final t = Curves.easeOutCubic.transform(_shown.value);
        return Offstage(
          offstage: keyboardOpen || _shown.value == 0,
          child: ClipRect(
            child: Align(
              alignment: Alignment.bottomCenter,
              heightFactor: t,
              child: Opacity(opacity: t, child: child),
            ),
          ),
        );
      },
    );
  }
}

/// Drives and recently opened resources as search last saw them.
class SearchCache {
  final List<DriveInfo> drives;
  final List<({String drive, RecentResource resource})> recent;

  const SearchCache(this.drives, this.recent);
}
