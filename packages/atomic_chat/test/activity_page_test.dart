import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// A host that pages: [total] entries, one every minute, newest first.
class PagedApi extends FakeApi {
  final int total;
  final List<int> pages = [];
  final List<bool> pagesMine = [];

  PagedApi(this.total)
      : super(activityList: [
          for (var i = 0; i < 5; i++) _entry(i),
        ]);

  static ActivityEntry _entry(int i) => ActivityEntry(
        subject: 'did:ad:n$i',
        drive: 'did:ad:drive',
        kind: 'changed',
        at: 1700000000000 - i * 60000,
        actor: 'Bob',
        name: 'Note $i',
        className: 'Document',
      );

  @override
  Future<List<ActivityEntry>> activityPage(
      {ActivityEntry? before,
      int limit = AssistantApi.activityPageSize,
      bool includeOwn = false}) async {
    final start = before == null ? 0 : int.parse(before.name.substring(5)) + 1;
    pages.add(start);
    pagesMine.add(includeOwn);
    return [for (var i = start; i < total && i < start + limit; i++) _entry(i)];
  }
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  Future<void> openAll(WidgetTester tester, PagedApi api) async {
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const ValueKey('section-show-all-activity')));
    await tester.ensureVisible(find.byKey(const ValueKey('section-show-all-activity')));
    await tester.pump();
    await tester.tap(find.byKey(const ValueKey('section-show-all-activity')));
    await tester.pumpAndSettle();
  }

  testWidgets('the full activity pages back in time to the end',
      (tester) async {
    final api = PagedApi(120);
    await openAll(tester, api);
    // The first page only.
    expect(api.pages, [0]);
    expect(find.text('Note 0'), findsOneWidget);
    expect(find.text("You're all caught up"), findsNothing);

    final list = find.byKey(const Key('activity-all-list'));
    // Scrolling to the end reads the next page, until there is none.
    for (var i = 0; i < 6; i++) {
      await tester.drag(list, const Offset(0, -200000));
      await tester.pumpAndSettle();
    }
    expect(api.pages, [0, 50, 100]);
    expect(find.text('Note 119'), findsOneWidget);
    expect(find.text("You're all caught up"), findsOneWidget);
    // Not pages again once the end was reached.
    expect(api.pages, [0, 50, 100]);
  });

  testWidgets('a short feed is caught up at once', (tester) async {
    final api = PagedApi(8);
    await openAll(tester, api);
    expect(api.pages, [0]);
    expect(find.text("You're all caught up"), findsOneWidget);
  });

  testWidgets('Show mine starts the feed over with the own changes',
      (tester) async {
    final api = PagedApi(60);
    await openAll(tester, api);
    expect(api.pagesMine, [false]);
    await tester.tap(find.byType(ShowMineChip));
    await tester.pumpAndSettle();
    expect(api.pagesMine.last, isTrue);
    expect(api.pages.last, 0);
    expect(find.text('Note 0'), findsOneWidget);
  });
}
