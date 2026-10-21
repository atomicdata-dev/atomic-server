import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'unimplemented_api.dart';

/// A host with a thousand AI chats, newest first, read in pages.
class ThousandChatsApi extends UnimplementedApi {
  ThousandChatsApi({this.total = 1000});

  final int total;
  final List<({int offset, int limit})> pages = [];
  final List<({String query, List<String> classes})> classSearches = [];
  final List<String> plainSearches = [];
  int warmed = 0;

  ChatSummary chat(int i) => (
        subject: 'did:ad:chat-$i',
        name: 'Chat $i',
        lastActivity: 1000 - i,
        emoji: null
      );

  @override
  Future<List<ChatSummary>> chats() async => [
        for (var i = 0; i < AssistantApi.chatsPageSize && i < total; i++)
          chat(i)
      ];

  @override
  Future<List<ChatSummary>> chatsPage(
      {required int offset, required int limit}) async {
    pages.add((offset: offset, limit: limit));
    return [
      for (var i = offset; i < offset + limit && i < total; i++) chat(i),
    ];
  }

  @override
  Future<List<DriveInfo>> drives() async =>
      [(subject: 'did:ad:drive', name: 'Home', emoji: null, picture: null)];
  @override
  Future<List<RecentResource>> recentResources(String drive) async => const [];
  @override
  Future<List<RecentResource>> favorites() async => const [];
  @override
  Future<List<NotificationItem>> notifications() async => const [];
  @override
  Future<List<ConversationRow>> conversations() async => const [];
  @override
  Future<List<ActivityEntry>> activity(int limit) async => const [];
  @override
  Future<Map<String, String>> resourceIcons(List<String> subjects) async =>
      const {};
  @override
  Future<String?> agentName() async => null;

  @override
  Future<void> warmSearch() async => warmed++;

  @override
  Future<List<SearchHit>> search(String query, {String? drive}) async {
    plainSearches.add(query);
    // The best hits are documents: a chat is not among them.
    return [
      for (var i = 0; i < 20; i++)
        (
          subject: 'did:ad:doc-$i',
          title: 'Document $i about $query',
          className: 'Document',
          classUrl: '',
          drive: 'did:ad:drive',
          score: 2.0,
          emoji: null,
          picture: null
        ),
    ];
  }

  @override
  Future<List<SearchHit>> searchClasses(String query,
      {String? drive, required List<String> classes}) async {
    classSearches.add((query: query, classes: classes));
    return [
      (
        subject: 'did:ad:chat-777',
        title: 'Chat 777 about $query',
        className: 'AiChat',
        classUrl: 'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-chat',
        drive: 'did:ad:drive',
        score: 0.1,
        emoji: null,
        picture: null
      ),
    ];
  }
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: home,
    );

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  int built(WidgetTester tester) =>
      tester.widgetList(find.byType(ResourceRow)).length;

  Future<void> openAll(WidgetTester tester, ThousandChatsApi api) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const ValueKey('section-show-all-chats')));
    await tester.ensureVisible(find.byKey(const ValueKey('section-show-all-chats')));
    await tester.pump();
    await tester.tap(find.byKey(const ValueKey('section-show-all-chats')));
    await tester.pumpAndSettle();
  }

  group('AI chats: All', () {
    testWidgets('builds only the rows in view, of a thousand', (tester) async {
      final api = ThousandChatsApi();
      await openAll(tester, api);
      expect(find.byKey(const Key('chats-all-list')), findsOneWidget);
      expect(find.text('Chat 0'), findsOneWidget);
      // A screenful (plus the cache extent), not 50 and not 1000.
      expect(built(tester), inInclusiveRange(5, 30));
      expect(find.text('Chat 40'), findsNothing);
    });

    testWidgets('reaching the end reads the next page, until all 1000',
        (tester) async {
      final api = ThousandChatsApi();
      await openAll(tester, api);
      // The home read the first 50; nothing more is asked while far from
      // the end.
      expect(api.pages, isEmpty);

      final list = find.byKey(const Key('chats-all-list'));
      var guard = 0;
      while (!find.text('Chat 999').evaluate().isNotEmpty && guard++ < 400) {
        await tester.fling(list, const Offset(0, -2000), 4000);
        await tester.pumpAndSettle();
      }
      expect(find.text('Chat 999'), findsOneWidget);
      // Pages follow each other from where the list ended, no gaps.
      expect(api.pages.first.offset, 50);
      for (var i = 1; i < api.pages.length; i++) {
        expect(api.pages[i].offset,
            api.pages[i - 1].offset + api.pages[i - 1].limit);
      }
      expect(api.pages.length, 20, reason: '19 full pages, then an empty one');
      // Everything arrived once; the last page was short, so no spinner.
      expect(find.byKey(const ValueKey('chats-loading')), findsNothing);
      // The scroll stays cheap: still only the rows in view are built.
      expect(built(tester), lessThan(30));
    });

    testWidgets('a page is read when within ten rows of the end',
        (tester) async {
      final api = ThousandChatsApi();
      await openAll(tester, api);
      final list = find.byKey(const Key('chats-all-list'));
      // Scroll to about row 20 of 50 (+ a heading): not yet near the end.
      await tester.drag(list, const Offset(0, -300));
      await tester.pumpAndSettle();
      expect(api.pages, isEmpty);
      await tester.drag(list, const Offset(0, -1500));
      await tester.pumpAndSettle();
      expect(api.pages, isNotEmpty);
      expect(api.pages.first.offset, 50);
    });

    testWidgets('a short list has one page and no more reads', (tester) async {
      final api = ThousandChatsApi(total: 7);
      await openAll(tester, api);
      expect(find.text('Chat 6'), findsOneWidget);
      expect(api.pages, isEmpty);
      expect(find.byKey(const ValueKey('chats-loading')), findsNothing);
    });
  });

  group('search', () {
    testWidgets(
        'the AI chats chip passes its class down and lists a hit '
        'the global top 20 does not hold', (tester) async {
      final api = ThousandChatsApi();
      await tester.pumpWidget(_app(SearchScreen(
          drive: 'did:ad:drive', api: api, kind: SearchKind.chats)));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'plan');
      await tester.pumpAndSettle();
      expect(api.plainSearches, isEmpty);
      expect(api.classSearches.last.query, 'plan');
      expect(api.classSearches.last.classes, ['aichat']);
      expect(find.text('Chat 777 about plan'), findsOneWidget);
    });

    testWidgets('Drives and Messages pass their classes', (tester) async {
      for (final (kind, classes) in [
        (SearchKind.drives, ['drive']),
        (SearchKind.messages, ['conversation', 'chatroom']),
      ]) {
        final api = ThousandChatsApi();
        await tester.pumpWidget(_app(SearchScreen(
            key: ValueKey(kind), drive: 'did:ad:drive', api: api, kind: kind)));
        await tester.pumpAndSettle();
        await tester.enterText(find.byType(TextField), 'x');
        await tester.pumpAndSettle();
        expect(api.classSearches.last.classes, classes, reason: '$kind');
      }
    });

    testWidgets('without a kind nothing is filtered', (tester) async {
      final api = ThousandChatsApi();
      await tester
          .pumpWidget(_app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'plan');
      await tester.pumpAndSettle();
      expect(api.classSearches, isEmpty);
      expect(api.plainSearches, ['plan']);
    });

    testWidgets('before typing, the chip lists every chat, not the home 50',
        (tester) async {
      final api = ThousandChatsApi();
      await tester.pumpWidget(_app(SearchScreen(
          drive: 'did:ad:drive', api: api, kind: SearchKind.chats)));
      await tester.pumpAndSettle();
      // The newest is nearest the field (the list is reversed): drag down
      // to the oldest chats; all 1000 were read, in pages of 200.
      expect(api.pages.map((p) => p.offset), [0, 200, 400, 600, 800, 1000]);
      await tester.dragUntilVisible(find.text('Chat 999'),
          find.byType(ListView).first, const Offset(0, 3000),
          maxIteration: 400);
      expect(find.text('Chat 999'), findsOneWidget);
    });
  });

  testWidgets('the search index is warmed once the home is drawn',
      (tester) async {
    final api = ThousandChatsApi();
    await tester.pumpWidget(_app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    expect(api.warmed, 1);
  });
}
