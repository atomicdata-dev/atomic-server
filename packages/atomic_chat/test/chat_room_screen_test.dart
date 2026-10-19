import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

const _t0 = 1700000000000;
const _minute = 60 * 1000;

ChatRoomMessage _msg(String id, String who, String text, int at,
        {bool mine = false}) =>
    (
      id: id,
      kind: ChatRoomKind.text,
      author: 'did:ad:agent:$who',
      authorName: who,
      mine: mine,
      text: text,
      createdAt: at,
      about: null,
      aboutTitle: '',
    );

ChatRoomMessage _event(String id, String who, String text, int at,
        {String? about, String title = ''}) =>
    (
      id: id,
      kind: ChatRoomKind.event,
      author: 'did:ad:agent:$who',
      authorName: who,
      mine: false,
      text: text,
      createdAt: at,
      about: about,
      aboutTitle: title,
    );

class _RoomApi extends UnimplementedApi {
  List<ChatRoomMessage> log;
  final List<(String, String)> sent = [];
  final List<String> opened = [];
  int reads = 0;
  Object? sendError;

  _RoomApi(this.log);

  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String s) async {
    reads++;
    return List.of(log);
  }

  @override
  Future<void> sendChatRoomMessage(String subject, String text) async {
    if (sendError != null) throw sendError!;
    sent.add((subject, text));
    log = [
      ...log,
      _msg('sent-${sent.length}', 'me', text, _t0 + 99 * _minute, mine: true),
    ];
  }

  @override
  void noteOpened(String drive, String subject) => opened.add(subject);
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: home,
    );

Future<void> _open(WidgetTester tester, _RoomApi api,
    {String title = 'Standup'}) async {
  await tester.pumpWidget(_app(ChatRoomScreen(
      api: api, drive: 'did:ad:drive', subject: 'did:ad:room', title: title)));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('parses the host JSON into messages and events', (tester) async {
    final parsed = AssistantJson.parseChatRoomMessages(jsonEncode([
      {
        'id': 'p#1',
        'kind': 'text',
        'author': 'a',
        'author_name': 'Alice',
        'mine': false,
        'text': 'Hi',
        'c': 5,
      },
      {
        'id': 'p#2',
        'kind': 'event',
        'author': 'a',
        'author_name': 'Alice',
        'text': 'Viewing [Roadmap](did:ad:x)',
        'c': 6,
        'about': 'did:ad:x',
        'about_title': 'Roadmap',
      },
      // A kind this app does not know is a plain message.
      {'id': 'p#3', 'kind': 'poll', 'text': 'odd', 'c': 7},
    ]));
    expect(parsed.map((m) => m.kind),
        [ChatRoomKind.text, ChatRoomKind.event, ChatRoomKind.text]);
    expect(parsed[1].about, 'did:ad:x');
    expect(parsed[1].aboutTitle, 'Roadmap');
    expect(parsed[2].text, 'odd');
  });

  testWidgets('shows messages as bubbles, mine on the right, with names',
      (tester) async {
    final api = _RoomApi([
      _msg('1', 'alice', 'Hi there', _t0),
      _msg('2', 'alice', 'Second', _t0 + _minute),
      _msg('3', 'me', 'Hello Alice', _t0 + 2 * _minute, mine: true),
    ]);
    await _open(tester, api);
    expect(
        find.descendant(
            of: find.byType(AppBar), matching: find.text('Standup')),
        findsOneWidget);

    final width = tester.view.physicalSize.width / tester.view.devicePixelRatio;
    expect(tester.getCenter(find.text('Hi there')).dx, lessThan(width / 2));
    expect(
        tester.getCenter(find.text('Hello Alice')).dx, greaterThan(width / 2));
    expect(tester.getTopLeft(find.text('Hello Alice')).dy,
        greaterThan(tester.getTopLeft(find.text('Hi there')).dy));
    // The name and the initial show once for alice's two messages.
    expect(
        tester
            .widgetList<Text>(find.byKey(const Key('message-author')))
            .map((t) => t.data),
        ['alice']);
    expect(find.byKey(const Key('message-avatar')), findsOneWidget);
    expect(find.text('A'), findsOneWidget);
  });

  testWidgets('an author whose name is not known yet shows a placeholder',
      (tester) async {
    final api = _RoomApi([
      (_msg('1', 'x', 'Hi', _t0)).toNamelessForTest(),
    ]);
    await _open(tester, api);
    expect(find.text('Unknown member'), findsOneWidget);
    expect(find.text('?'), findsOneWidget);
  });

  testWidgets('events are compact lines, a viewing line opens the resource',
      (tester) async {
    final api = _RoomApi([
      _msg('1', 'alice', 'Let us start', _t0),
      _event('2', 'Joep', 'Viewing [Roadmap](did:ad:road)', _t0 + _minute,
          about: 'did:ad:road', title: 'Roadmap'),
      _event('3', 'Joep', 'Started the meeting.', _t0 + 2 * _minute),
    ]);
    await _open(tester, api);

    expect(find.text('Joep is viewing Roadmap'), findsOneWidget);
    expect(find.text('Joep · Started the meeting.'), findsOneWidget);
    // Events are not bubbles: no author header or avatar for them.
    expect(find.byKey(const Key('message-avatar')), findsOneWidget);
    expect(find.byKey(const Key('event-row')), findsNWidgets(2));
    // One line each.
    final line = tester.getSize(find.byKey(const Key('event-row')).first);
    expect(line.height, lessThan(40));

    // The viewing line is tappable and opens the resource over the room.
    ResourceView.pageFactory = (send) => _NoPage();
    ResourceView.flushTimeout = const Duration(milliseconds: 1);
    ResourceView.releaseDelay = const Duration(milliseconds: 1);
    addTearDown(() {
      ResourceView.pageFactory = null;
      ResourceView.flushTimeout = const Duration(seconds: 2);
      ResourceView.releaseDelay = const Duration(seconds: 3);
    });
    await tester.tap(find.text('Joep is viewing Roadmap'));
    await tester.pumpAndSettle();
    expect(api.opened, ['did:ad:road']);
    expect(find.byType(ResourceView), findsOneWidget);

    // Close everything, so no timer outlives the test.
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  testWidgets('an event without a target is not tappable', (tester) async {
    final api = _RoomApi([_event('1', 'Joep', 'Ended.', _t0)]);
    await _open(tester, api);
    await tester.tap(find.text('Joep · Ended.'));
    await tester.pumpAndSettle();
    expect(api.opened, isEmpty);
    expect(find.byType(ResourceView), findsNothing);
  });

  testWidgets('shows an empty room', (tester) async {
    await _open(tester, _RoomApi([]));
    expect(find.text('No messages yet'), findsOneWidget);
  });

  testWidgets('send is off while the field is empty, then sends and clears',
      (tester) async {
    final api = _RoomApi([_msg('1', 'alice', 'Hi', _t0)]);
    await _open(tester, api);
    IconButton send() => tester.widget(find.byType(IconButton));
    expect(send().onPressed, isNull);

    await tester.enterText(find.byType(TextField), '  Hello room  ');
    await tester.pump();
    expect(send().onPressed, isNotNull);
    await tester.tap(find.byType(IconButton));
    await tester.pumpAndSettle();

    expect(api.sent, [('did:ad:room', 'Hello room')]);
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
        isEmpty);
    // Shown once, read back from the room.
    expect(find.text('Hello room'), findsOneWidget);
  });

  testWidgets('a message that fails to send says so and keeps the text',
      (tester) async {
    final api = _RoomApi([])..sendError = 'offline';
    await _open(tester, api);
    await tester.enterText(find.byType(TextField), 'Hello');
    await tester.pump();
    await tester.tap(find.byType(IconButton));
    await tester.pumpAndSettle();
    expect(find.textContaining("Couldn't send"), findsOneWidget);
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
        'Hello');
  });

  testWidgets('new messages arrive on their own', (tester) async {
    final api = _RoomApi([_msg('1', 'alice', 'Hi', _t0)]);
    await _open(tester, api);
    api.log = [...api.log, _msg('2', 'alice', 'Anyone there?', _t0 + _minute)];
    await tester.pump(conversationRefresh);
    await tester.pumpAndSettle();
    expect(find.text('Anyone there?'), findsOneWidget);
  });

  testWidgets('an unreadable room shows the error', (tester) async {
    await tester.pumpWidget(_app(
        ChatRoomScreen(api: const UnimplementedApi(), subject: 'did:ad:room')));
    await tester.pumpAndSettle();
    expect(find.textContaining('chatRoomMessages'), findsOneWidget);
    expect(find.text('Chat'), findsOneWidget);
  });

  test('a chat room opens natively from anywhere', () {
    expect(hasNativeView('chatroom'), isTrue);
    expect(hasNativeView('https://atomicdata.dev/classes/ChatRoom'), isTrue);
    // A meeting page stays the web page (notes and all).
    expect(hasNativeView('meeting'), isFalse);
    final view = openResourceView(
        api: const UnimplementedApi(),
        drive: 'd',
        subject: 's',
        className: 'chatroom');
    expect(view, isA<ChatRoomScreen>());
  });
}

class _NoPage implements EmbedPage {
  @override
  Future<void> runJavaScript(String script) async {}
  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;
  @override
  Widget build() => const SizedBox();
}

extension on ChatRoomMessage {
  ChatRoomMessage toNamelessForTest() => (
        id: id,
        kind: kind,
        author: author,
        authorName: '',
        mine: mine,
        text: text,
        createdAt: createdAt,
        about: about,
        aboutTitle: aboutTitle,
      );
}
