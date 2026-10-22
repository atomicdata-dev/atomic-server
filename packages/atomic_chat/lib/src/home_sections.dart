import 'package:shared_preferences/shared_preferences.dart';

/// A section of the Home screen.
enum HomeSection {
  drives('Drives'),
  notifications('Notifications'),
  activity('Activity'),
  messages('Messages'),
  favorites('Favorites'),
  chats('AI chats');

  final String title;
  const HomeSection(this.title);

  static HomeSection? byName(String name) {
    for (final s in values) {
      if (s.name == name) return s;
    }
    return null;
  }
}

/// The sections that are panels at the bottom of the home, in the web
/// sidebar's order (the drives are not one: the current drive's tree is).
const homePanelSections = [
  HomeSection.notifications,
  HomeSection.activity,
  HomeSection.messages,
  HomeSection.favorites,
  HomeSection.chats,
];

/// A section as the Home button's menu lists it: whether the person hid it
/// from the home, and how many rows it has (null until known).
typedef HomeSectionEntry = ({HomeSection section, bool hidden, int? count});

/// SharedPreferences keys of the Home layout (per device).
const homeOrderKey = 'home_sections_order';
const homeHiddenKey = 'home_sections_hidden';
const homeCollapsedKey = 'home_sections_collapsed';

/// Which Home sections show, in which order, and which are folded to their
/// heading. Immutable; every change returns a new layout. Defaults to every
/// section, in the order of [HomeSection.values].
class HomeLayout {
  /// Every section, in the order shown (hidden ones keep their place).
  final List<HomeSection> order;
  final Set<HomeSection> hidden;
  final Set<HomeSection> collapsed;

  const HomeLayout({
    this.order = HomeSection.values,
    this.hidden = const {},
    this.collapsed = const {},
  });

  /// The sections that show, in order.
  List<HomeSection> get visible => [
        for (final s in order)
          if (!hidden.contains(s)) s,
      ];

  /// Built from stored names: unknown names are dropped, and a section the
  /// store does not know yet (added by an update) goes in at its default
  /// place, right after the last stored section that precedes it by default.
  factory HomeLayout.fromNames({
    List<String>? order,
    List<String>? hidden,
    List<String>? collapsed,
  }) {
    Set<HomeSection> sections(List<String>? names) => {
          for (final n in names ?? const <String>[])
            if (HomeSection.byName(n) != null) HomeSection.byName(n)!,
        };
    final result = <HomeSection>[];
    for (final n in order ?? const <String>[]) {
      final s = HomeSection.byName(n);
      if (s != null && !result.contains(s)) result.add(s);
    }
    for (final s in HomeSection.values) {
      if (result.contains(s)) continue;
      // After the last stored section that comes before it by default.
      final before = result.lastIndexWhere((o) => o.index < s.index);
      result.insert(before + 1, s);
    }
    return HomeLayout(
      order: result,
      hidden: sections(hidden),
      collapsed: sections(collapsed),
    );
  }

  HomeLayout _with({
    List<HomeSection>? order,
    Set<HomeSection>? hidden,
    Set<HomeSection>? collapsed,
  }) =>
      HomeLayout(
        order: order ?? this.order,
        hidden: hidden ?? this.hidden,
        collapsed: collapsed ?? this.collapsed,
      );

  /// The layout of a fresh install: every panel closed.
  static const closed = HomeLayout(collapsed: {
    HomeSection.drives,
    HomeSection.notifications,
    HomeSection.activity,
    HomeSection.messages,
    HomeSection.favorites,
    HomeSection.chats,
  });

  /// What a device with nothing saved starts with (tests start from another).
  static HomeLayout fresh = closed;

  /// Forces the compact (accordion) behaviour of the panels on or off; null
  /// follows the window. For tests.
  static bool? accordionOverride;

  /// Only [s] open, every other section folded.
  HomeLayout openOnly(HomeSection s) => _with(collapsed: {
        for (final o in HomeSection.values)
          if (o != s) o
      });

  HomeLayout toggleCollapsed(HomeSection s) => _with(
        collapsed: collapsed.contains(s)
            ? (Set.of(collapsed)..remove(s))
            : (Set.of(collapsed)..add(s)),
      );

  HomeLayout setHidden(HomeSection s, bool hide) => _with(
        hidden: hide ? (Set.of(hidden)..add(s)) : (Set.of(hidden)..remove(s)),
      );

  /// The full order with the row at `from` moved to index `to`
  /// ([ReorderableListView.onReorderItem] indices).
  HomeLayout reorder(int from, int to) {
    final list = List.of(order);
    list.insert(to, list.removeAt(from));
    return _with(order: list);
  }

  /// Default order, every section on; folds are kept.
  HomeLayout reset() => HomeLayout(collapsed: collapsed);

  bool canMove(HomeSection s, int delta) => _neighbour(s, delta) != null;

  /// The visible section next to `s` in direction `delta` (-1 up, 1 down).
  HomeSection? _neighbour(HomeSection s, int delta) {
    final v = visible;
    final i = v.indexOf(s);
    final j = i + delta;
    if (i < 0 || j < 0 || j >= v.length) return null;
    return v[j];
  }

  /// `s` swapped with the visible section above (-1) or below (1) it.
  HomeLayout move(HomeSection s, int delta) {
    final other = _neighbour(s, delta);
    if (other == null) return this;
    final list = List.of(order);
    final a = list.indexOf(s);
    final b = list.indexOf(other);
    list[a] = other;
    list[b] = s;
    return _with(order: list);
  }

  static Future<HomeLayout> load() async {
    try {
      final p = await SharedPreferences.getInstance();
      return HomeLayout.fromNames(
        order: p.getStringList(homeOrderKey),
        hidden: p.getStringList(homeHiddenKey),
        collapsed: p.getStringList(homeCollapsedKey) ??
            [for (final s in fresh.collapsed) s.name],
      );
    } catch (_) {
      return fresh;
    }
  }

  Future<void> save() async {
    try {
      final p = await SharedPreferences.getInstance();
      await p.setStringList(homeOrderKey, [for (final s in order) s.name]);
      await p.setStringList(homeHiddenKey, [for (final s in hidden) s.name]);
      await p
          .setStringList(homeCollapsedKey, [for (final s in collapsed) s.name]);
    } catch (_) {}
  }
}
