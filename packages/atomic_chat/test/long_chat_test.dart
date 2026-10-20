import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

const _t0 = 1700000000000;

ChatRoomMessage _line(int i) => (
      id: 'm$i',
      kind: ChatRoomKind.text,
      author: 'did:ad:agent:${i % 3}',
      authorName: 'Person ${i % 3}',
      mine: i % 3 == 0,
      text: 'Line $i',
      createdAt: _t0 + i * 20000,
      about: null,
      aboutTitle: '',
    );

/// A room of [n] lines, read only in windows: a whole read fails the test.
class _LongRoom extends UnimplementedApi {
  final List<ChatRoomMessage> log;
  int pageReads = 0;
  int afterReads = 0;
  int maxLimit = 0;

  /// When set, an older page waits for it.
  Completer<void>? holdOlder;

  _LongRoom(int n) : log = List.generate(n, _line, growable: true);

  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String subject) =>
      throw StateError('a long room is never read whole');

  @override
  Future<ChatPage<ChatRoomMessage>> chatRoomMessagesPage(String subject,
      {String? before, int limit = 50}) async {
    pageReads++;
    if (limit > maxLimit) maxLimit = limit;
    if (before != null && holdOlder != null) await holdOlder!.future;
    return pageOfAll(log, before, limit);
  }

  @override
  Future<ChatPage<ChatRoomMessage>> chatRoomMessagesAfter(
      String subject, String after,
      {int limit = 100}) async {
    afterReads++;
    return afterOfAll(log, after, limit);
  }

  @override
  Future<void> sendChatRoomMessage(String subject, String text) async {
    log.add((
      id: 'sent${log.length}',
      kind: ChatRoomKind.text,
      author: 'did:ad:agent:0',
      authorName: 'Person 0',
      mine: true,
      text: text,
      createdAt: DateTime.now().millisecondsSinceEpoch,
      about: null,
      aboutTitle: '',
    ));
  }
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: home,
    );

Future<void> _open(WidgetTester tester, _LongRoom api) async {
  await tester.pumpWidget(_app(ChatRoomScreen(
      api: api, drive: 'did:ad:drive', subject: 'did:ad:room', title: 'Room')));
  await tester.pumpAndSettle();
}

/// Lines on screen (built), by their row key.
Iterable<String> _built(WidgetTester tester) => tester
    .widgetList<KeyedSubtree>(find.byType(KeyedSubtree))
    .map((w) => w.key)
    .whereType<ValueKey<String>>()
    .map((k) => k.value)
    .where((id) => RegExp(r'^m\d+$').hasMatch(id));

Finder _row(String id) => find.byKey(ValueKey(id));

Future<void> _leave(WidgetTester tester) async {
  // Stop the poll timer.
  await tester.pumpWidget(const SizedBox());
}

void main() {
  testWidgets('a room of 200 000 lines opens with its newest page only',
      (tester) async {
    final api = _LongRoom(200000);
    await _open(tester, api);
    expect(api.pageReads, 1);
    expect(api.maxLimit, lessThanOrEqualTo(50));
    expect(find.text('Line 199999'), findsOneWidget);
    // Only what fits (and the cache extent) is built.
    expect(_built(tester).length, lessThan(40));
    await _leave(tester);
  });

  testWidgets('scrolling up reads older pages without moving what is shown',
      (tester) async {
    final api = _LongRoom(200000);
    await _open(tester, api);
    final list = find.byType(Scrollable).first;
    // Up until the next page is asked for (within 15 rows of the top).
    api.holdOlder = Completer();
    for (var i = 0; i < 20 && api.pageReads < 2; i++) {
      await tester.drag(list, const Offset(0, 300));
      await tester.pump();
    }
    expect(api.pageReads, 2, reason: 'the older page was asked for');
    await tester.pumpAndSettle();
    // A line on screen, and where it is, before the page arrives.
    final ys = {
      for (final id in _built(tester)) id: tester.getTopLeft(_row(id)).dy
    };
    final anchor = _row(ys.entries
        .where((e) => e.value > 0 && e.value < 600)
        .reduce((a, b) => a.value < b.value ? a : b)
        .key);
    final before = tester.getTopLeft(anchor).dy;
    api.holdOlder!.complete();
    await tester.pumpAndSettle();
    expect(tester.getTopLeft(anchor).dy, before);
    // The page is there: the line just above the first window.
    for (var i = 0;
        i < 20 && find.text('Line 199949').evaluate().isEmpty;
        i++) {
      await tester.drag(list, const Offset(0, 300));
      await tester.pumpAndSettle();
    }
    expect(find.text('Line 199949'), findsOneWidget);
    await _leave(tester);
  });

  testWidgets(
      'new lines while scrolled up wait behind "Jump to latest" with a count',
      (tester) async {
    final api = _LongRoom(5000);
    await _open(tester, api);
    final list = find.byType(Scrollable).first;
    for (var i = 0; i < 4; i++) {
      await tester.drag(list, const Offset(0, 400));
      await tester.pumpAndSettle();
    }
    expect(find.byKey(const Key('jump-to-latest')), findsOneWidget);
    final shown = _built(tester).toList();
    for (var i = 0; i < 3; i++) {
      api.log.add(_line(5000 + i));
    }
    await tester.pump(conversationRefresh);
    await tester.pumpAndSettle();
    // Nothing moved; the count is on the button.
    expect(_built(tester).toList(), shown);
    expect(find.text('3'), findsOneWidget);
    await tester.tap(find.byKey(const Key('jump-to-latest')));
    await tester.pumpAndSettle();
    expect(find.text('Line 5002'), findsOneWidget);
    expect(find.byKey(const Key('jump-to-latest')), findsNothing);
    await _leave(tester);
  });

  testWidgets('at the bottom new lines show at once', (tester) async {
    final api = _LongRoom(300);
    await _open(tester, api);
    api.log.add(_line(300));
    await tester.pump(conversationRefresh);
    await tester.pumpAndSettle();
    expect(find.text('Line 300'), findsOneWidget);
    expect(api.afterReads, greaterThan(0));
    await _leave(tester);
  });

  testWidgets('a day separator heads the first line of a day', (tester) async {
    final api = _LongRoom(3);
    await _open(tester, api);
    expect(find.byKey(const Key('day-separator')), findsWidgets);
    await _leave(tester);
  });

  group('ChatWindow', () {
    ChatWindow<int> window(List<int> all, {int max = 200}) => ChatWindow<int>(
          readPage: (before, limit) async => pageOfAll(all, before, limit),
          readAfter: (after, limit) async => afterOfAll(all, after, limit),
          idOf: (i) => '$i',
          pageSize: 50,
          maxItems: max,
        );

    test('stays bounded both ways and comes back without gaps', () async {
      final all = List.generate(200000, (i) => i);
      final w = window(all);
      await w.open();
      expect(w.items, List.generate(50, (i) => 199950 + i));
      // Far up: the newest pages go.
      for (var i = 0; i < 40; i++) {
        await w.loadOlder();
        w.trimNewest();
        expect(w.items.length, lessThanOrEqualTo(200 + 50));
        // Contiguous.
        expect(w.items.last - w.items.first, w.items.length - 1);
      }
      expect(w.detached, isTrue);
      final top = w.items.first;
      expect(top, 199950 - 40 * 50);
      // Back down: newer pages, the oldest go.
      while (w.detached) {
        await w.loadNewer();
        w.trimOldest();
        expect(w.items.last - w.items.first, w.items.length - 1);
        expect(w.items.length, lessThanOrEqualTo(200 + 50));
      }
      expect(w.items.last, 199999);
    });

    test('polls at the bottom add, scrolled up they wait', () async {
      final all = List.generate(100, (i) => i);
      final w = window(all);
      await w.open();
      all.addAll([100, 101]);
      await w.poll(atBottom: true);
      expect(w.items.last, 101);
      all.add(102);
      await w.poll(atBottom: false);
      expect(w.items.last, 101);
      expect(w.unseen, 1);
      await w.jumpToLatest();
      expect(w.items.last, 102);
      expect(w.unseen, 0);
      // Nothing is listed twice.
      expect(w.items.toSet().length, w.items.length);
    });

    test('opens at a cursor (a search hit), detached from the newest',
        () async {
      final all = List.generate(1000, (i) => i);
      final w = window(all);
      await w.openAt('500');
      expect(w.items.last, 499);
      expect(w.detached, isTrue);
      await w.loadNewer();
      expect(w.items.last, 549);
    });
  });
}
