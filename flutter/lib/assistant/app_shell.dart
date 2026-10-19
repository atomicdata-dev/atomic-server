import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';

import 'app_bottom_bar.dart';
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
          Expanded(
            // The bar below takes the system inset; the pages must not
            // reserve it a second time.
            child: MediaQuery.removePadding(
              context: context,
              removeBottom: true,
              child: Navigator(
                key: _shell.navigatorKey,
                observers: [_observer],
                onGenerateRoute: (_) => MaterialPageRoute<void>(
                  builder: (_) => widget.home,
                ),
              ),
            ),
          ),
          AppBottomBar(api: widget.api, shell: _shell),
        ]),
      ),
    );
  }
}
