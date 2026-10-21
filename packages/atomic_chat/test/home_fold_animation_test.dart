import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

RecentResource _r(String subject, String title) => (
      subject: subject,
      title: title,
      className: 'document-v2',
      classUrl: '',
      openedAt: 1,
      emoji: null,
      picture: null,
    );

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:home',
      home: ChatsScreen(drive: 'did:ad:home', api: api),
    ));

Finder _heading(String name) => find.byKey(ValueKey('home-panel-$name'));

/// The animated box around the favorites rows: the clip while folding, the
/// rows' own boundary at rest (no clip, fade or opacity layer then).
Finder get _box {
  final clip = find.ancestor(
      of: find.text('Fav 0'),
      matching: find.byWidgetPredicate(
          (w) => w is Align && w.heightFactor != null));
  if (clip.evaluate().isNotEmpty) return clip;
  return find.ancestor(
      of: find.text('Fav 0'),
      matching: find.byWidgetPredicate(
          (w) => w is RepaintBoundary && w.key is GlobalKey));
}

double _turns(WidgetTester tester) => tester
    .widget<RotationTransition>(find.descendant(
        of: _heading('favorites'), matching: find.byType(RotationTransition)))
    .turns
    .value;

void main() {
  late FakeApi api;

  setUp(() {
    ResourceView.serverFactory = () async => throw 'no server in a test';
    api = FakeApi(
      favoriteList: [for (var i = 0; i < 3; i++) _r('did:ad:f$i', 'Fav $i')],
    );
  });

  Future<void> boot(WidgetTester tester, Map<String, Object> prefs) async {
    SharedPreferences.setMockInitialValues(prefs);
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(400, 3200);
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
  }

  testWidgets('collapsing shrinks and fades, then drops the rows',
      (tester) async {
    await boot(tester, {});
    final full = tester.getSize(_box.first).height;
    expect(full, greaterThan(100));
    expect(_turns(tester), 0);

    await tester.tap(_heading('favorites'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 40));
    final mid = tester.getSize(_box.first).height;
    expect(mid, greaterThan(0));
    expect(mid, lessThan(full));
    expect(_turns(tester), inExclusiveRange(-0.25, 0));
    expect(find.text('Fav 0'), findsOneWidget);

    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Fav 0'), findsNothing);
    expect(_turns(tester), -0.25);
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getStringList(homeCollapsedKey), ['favorites']);
  });

  testWidgets('expanding grows within 180 ms', (tester) async {
    await boot(tester, {
      homeCollapsedKey: ['favorites'],
    });
    expect(find.text('Fav 0'), findsNothing);
    expect(_turns(tester), -0.25);

    await tester.tap(_heading('favorites'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 40));
    final mid = tester.getSize(_box.first).height;
    expect(mid, greaterThan(0));
    expect(_turns(tester), inExclusiveRange(-0.25, 0));

    await tester.pump(const Duration(milliseconds: 160));
    final full = tester.getSize(_box.first).height;
    expect(full, greaterThan(mid));
    expect(_turns(tester), 0);
  });

  testWidgets(
      'an open section is not clipped or faded (no layer over its rows)',
      (tester) async {
    await boot(tester, {});
    final section = find.ancestor(
        of: find.text('Fav 0'),
        matching: find.byWidgetPredicate(
            (w) => w is RepaintBoundary && w.key is GlobalKey));
    // Its direct parent is the section's builder, not a fade.
    Widget? parent;
    tester.element(section.first).visitAncestorElements((e) {
      parent = e.widget;
      return false;
    });
    expect(parent, isNot(isA<FadeTransition>()));
    expect(parent, isNot(isA<Align>()));
  });

  testWidgets('reduced motion is instant', (tester) async {
    tester.platformDispatcher.accessibilityFeaturesTestValue =
        const FakeAccessibilityFeatures(disableAnimations: true);
    addTearDown(tester.platformDispatcher.clearAccessibilityFeaturesTestValue);
    await boot(tester, {});

    await tester.tap(_heading('favorites'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 1));
    expect(find.text('Fav 0'), findsNothing);
    expect(_turns(tester), -0.25);

    await tester.tap(_heading('favorites'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 1));
    expect(find.text('Fav 0'), findsOneWidget);
    expect(_turns(tester), 0);
  });
}
