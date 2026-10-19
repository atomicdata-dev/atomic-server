import 'package:atomic_chat/src/home_sections.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  test('the default layout shows every section in the declared order', () {
    const layout = HomeLayout();
    expect(layout.visible, HomeSection.values);
  });

  test('move swaps with the visible neighbour and skips hidden sections', () {
    var layout = const HomeLayout().setHidden(HomeSection.recents, true);
    expect(layout.canMove(HomeSection.drives, -1), isFalse);
    layout = layout.move(HomeSection.activity, -1);
    expect(layout.visible.take(2), [HomeSection.activity, HomeSection.drives]);
    // Recents kept its slot in the full order.
    expect(layout.order.contains(HomeSection.recents), isTrue);
  });

  test('stored names: unknown dropped, new sections go to their place', () {
    final layout = HomeLayout.fromNames(
      order: ['chats', 'bogus', 'drives', 'chats'],
      hidden: ['drives', 'bogus'],
    );
    expect(layout.order.first, HomeSection.chats);
    expect(layout.order.toSet(), HomeSection.values.toSet());
    expect(layout.order.length, HomeSection.values.length);
    expect(layout.hidden, {HomeSection.drives});
  });

  test('persists per device', () async {
    SharedPreferences.setMockInitialValues({});
    await const HomeLayout()
        .move(HomeSection.chats, -1)
        .toggleCollapsed(HomeSection.recents)
        .setHidden(HomeSection.messages, true)
        .save();
    final loaded = await HomeLayout.load();
    expect(loaded.order.indexOf(HomeSection.chats),
        HomeSection.values.indexOf(HomeSection.chats) - 1);
    expect(loaded.collapsed, {HomeSection.recents});
    expect(loaded.hidden, {HomeSection.messages});
  });
}
