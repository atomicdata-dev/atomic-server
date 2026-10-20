import 'package:shared_preferences/shared_preferences.dart';

/// A section of the Home screen.
enum HomeSection {
  notifications('Notifications'),
  drives('Drives'),
  activity('Activity'),
  chats('AI chats'),
  favorites('Favorites'),
  messages('Messages');

  final String title;
  const HomeSection(this.title);

  static HomeSection? byName(String name) {
    for (final s in values) {
      if (s.name == name) return s;
    }
    return null;
  }
}

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
        collapsed: p.getStringList(homeCollapsedKey),
      );
    } catch (_) {
      return const HomeLayout();
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
