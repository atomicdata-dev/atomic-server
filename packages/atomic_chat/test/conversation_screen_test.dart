import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

const _t0 = 1700000000000;
const _minute = 60 * 1000;

ConversationMessage _msg(String id, String who, String text, int at,
        {bool mine = false}) =>
    (
      id: id,
      author: 'did:ad:agent:$who',
      authorName: who,
      mine: mine,
      text: text,
      createdAt: at,
    );

class _ConversationApi extends UnimplementedApi {
  List<ConversationMessage> log;
  final List<(String, String)> sent = [];
  final List<String> followed = [];
  int reads = 0;
  Object? sendError;
  final ValueNotifier<int> changes = ValueNotifier(0);

  @override
  Listenable? get storeChanges => changes;

  _ConversationApi(this.log);

  @override
  Future<List<ConversationMessage>> conversationMessages(String s) async {
    reads++;
    return List.of(log);
  }

  @override
  Future<void> sendConversationMessage(String subject, String text) async {
    if (sendError != null) throw sendError!;
    sent.add((subject, text));
    log = [
      ...log,
      _msg('sent-${sent.length}', 'me', text, _t0 + 99 * _minute, mine: true),
    ];
  }

  @override
  Future<void> followConversation(String subject) async =>
      followed.add(subject);
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: home,
    );

Future<void> _open(WidgetTester tester, _ConversationApi api,
    {String title = 'Alice'}) async {
  await tester.pumpWidget(_app(
      ConversationScreen(api: api, subject: 'did:ad:convo', title: title)));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('a finished sync shows what arrived without waiting for the poll',
      (tester) async {
    final api = _ConversationApi([_msg('1', 'alice', 'Hi there', _t0)]);
    await _open(tester, api);
    expect(find.text('Sent while away'), findsNothing);
    api.log = [
      ...api.log,
      _msg('2', 'alice', 'Sent while away', _t0 + _minute)
    ];
    api.changes.value++;
    await tester.pumpAndSettle();
    expect(find.text('Sent while away'), findsOneWidget);
  });

  testWidgets(
      'shows the other members in the title and the messages as '
      'bubbles, mine on the right', (tester) async {
    final api = _ConversationApi([
      _msg('1', 'alice', 'Hi there', _t0),
      _msg('2', 'me', 'Hello Alice', _t0 + _minute, mine: true),
    ]);
    await _open(tester, api, title: 'Alice');
    expect(api.followed, ['did:ad:convo']);
    expect(
        tester
            .widget<Text>(find.descendant(
                of: find.byType(AppBar),
                matching: find.byKey(const Key('chat-header-title'))))
            .data,
        'Alice');

    final width = tester.view.physicalSize.width / tester.view.devicePixelRatio;
    final theirs = tester.getCenter(find.text('Hi there')).dx;
    final mine = tester.getCenter(find.text('Hello Alice')).dx;
    expect(theirs, lessThan(width / 2));
    expect(mine, greaterThan(width / 2));
    // Newest at the bottom.
    expect(tester.getTopLeft(find.text('Hello Alice')).dy,
        greaterThan(tester.getTopLeft(find.text('Hi there')).dy));
  });

  testWidgets('a group chat names the author above their messages once',
      (tester) async {
    final api = _ConversationApi([
      _msg('1', 'alice', 'one', _t0),
      _msg('2', 'alice', 'two', _t0 + _minute),
      _msg('3', 'bob', 'three', _t0 + 2 * _minute),
      _msg('4', 'me', 'four', _t0 + 3 * _minute, mine: true),
    ]);
    await _open(tester, api, title: 'Alice, Bob');
    final names = tester
        .widgetList<Text>(find.byKey(const Key('message-author')))
        .map((t) => t.data)
        .toList();
    // Once each: alice's second message has no name of its own.
    expect(names, unorderedEquals(['alice', 'bob']));
  });

  testWidgets('a two-person chat does not repeat the other name',
      (tester) async {
    final api = _ConversationApi([
      _msg('1', 'alice', 'one', _t0),
      _msg('2', 'alice', 'two', _t0 + _minute),
    ]);
    await _open(tester, api);
    expect(find.byKey(const Key('message-author')), findsNothing);
  });

  testWidgets('the time shows once under a group of messages', (tester) async {
    final api = _ConversationApi([
      _msg('1', 'alice', 'one', _t0),
      _msg('2', 'alice', 'two', _t0 + _minute),
      // A long pause starts a new group.
      _msg('3', 'alice', 'three', _t0 + 30 * _minute),
    ]);
    await _open(tester, api);
    expect(find.byKey(const Key('message-time')), findsNWidgets(2));
  });

  testWidgets('a message that cannot be opened says so', (tester) async {
    final api = _ConversationApi([
      (
        id: '1',
        author: 'did:ad:agent:alice',
        authorName: 'alice',
        mine: false,
        text: null,
        createdAt: _t0,
      ),
    ]);
    await _open(tester, api);
    expect(find.text("This message can't be opened"), findsOneWidget);
  });

  testWidgets('send is off while the field is empty, then sends and clears',
      (tester) async {
    final api = _ConversationApi([_msg('1', 'alice', 'Hi', _t0)]);
    await _open(tester, api);

    IconButton send() => tester.widget<IconButton>(
        find.widgetWithIcon(IconButton, Icons.arrow_upward));
    expect(send().onPressed, isNull);

    await tester.enterText(find.byType(TextField), '   ');
    await tester.pump();
    expect(send().onPressed, isNull);

    await tester.enterText(find.byType(TextField), 'Hello');
    await tester.pump();
    expect(send().onPressed, isNotNull);
    await tester.tap(find.byIcon(Icons.arrow_upward));
    await tester.pumpAndSettle();

    expect(api.sent, [('did:ad:convo', 'Hello')]);
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
        isEmpty);
    expect(find.text('Hello'), findsOneWidget);
    expect(send().onPressed, isNull);
  });

  testWidgets('the field keeps focus after sending from the keyboard',
      (tester) async {
    final api = _ConversationApi(const []);
    await _open(tester, api);
    await tester.tap(find.byType(TextField));
    await tester.enterText(find.byType(TextField), 'first');
    await tester.testTextInput.receiveAction(TextInputAction.send);
    await tester.pumpAndSettle();
    expect(api.sent, [('did:ad:convo', 'first')]);
    final field = tester.widget<TextField>(find.byType(TextField));
    expect(field.focusNode!.hasFocus, isTrue);
  });

  testWidgets('a failed send shows why and puts the text back', (tester) async {
    final api = _ConversationApi(const [])..sendError = 'offline';
    await _open(tester, api);
    await tester.enterText(find.byType(TextField), 'Hello');
    await tester.pump();
    await tester.tap(find.byIcon(Icons.arrow_upward));
    await tester.pumpAndSettle();
    expect(find.textContaining('offline'), findsOneWidget);
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
        'Hello');
  });

  testWidgets('messages that arrive show up on the next refresh',
      (tester) async {
    final api = _ConversationApi([_msg('1', 'alice', 'Hi', _t0)]);
    await _open(tester, api);
    expect(find.text('Later one'), findsNothing);

    api.log = [
      ...api.log,
      _msg('2', 'alice', 'Later one', _t0 + _minute),
    ];
    final before = api.reads;
    await tester.pump(conversationRefresh);
    await tester.pumpAndSettle();
    expect(api.reads, greaterThan(before));
    expect(find.text('Later one'), findsOneWidget);
  });

  testWidgets('it does not poll while another screen is on top',
      (tester) async {
    final api = _ConversationApi([_msg('1', 'alice', 'Hi', _t0)]);
    await _open(tester, api);
    final navigator = tester.state<NavigatorState>(find.byType(Navigator));
    navigator.push(MaterialPageRoute<void>(
        builder: (_) => const Scaffold(body: Text('on top'))));
    await tester.pumpAndSettle();

    final before = api.reads;
    await tester.pump(conversationRefresh * 3);
    expect(api.reads, before);

    navigator.pop();
    await tester.pumpAndSettle();
    await tester.pump(conversationRefresh);
    expect(api.reads, greaterThan(before));
  });

  testWidgets(
      'the registry opens conversations natively, other classes in '
      'the web view', (tester) async {
    ResourceView.serverFactory = () async => throw 'no server in a test';
    final api = _ConversationApi(const []);
    Widget open(String classUrl) => openResourceView(
        api: api,
        drive: 'did:ad:drive',
        subject: 'did:ad:convo',
        title: 'Alice',
        classUrl: classUrl);

    await tester.pumpWidget(_app(open('https://atomicdata.dev/classes/Conversation')));
    await tester.pumpAndSettle();
    expect(find.byType(ConversationScreen), findsOneWidget);
    expect(find.byType(ResourceView), findsNothing);

    // Exact: the display name or a lowercased URL is not the class.
    for (final other in ['conversation', 'Conversation']) {
      await tester.pumpWidget(_app(open(other)));
      await tester.pumpAndSettle();
      expect(find.byType(ConversationScreen), findsNothing, reason: other);
    }

    await tester.pumpWidget(_app(open('https://atomicdata.dev/classes/Document')));
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsOneWidget);
    expect(find.byType(ConversationScreen), findsNothing);
  });

  test('messageTime shows the clock today and the date otherwise', () {
    final now = DateTime(2026, 10, 19, 12);
    int at(DateTime d) => d.millisecondsSinceEpoch;
    expect(messageTime(at(DateTime(2026, 10, 19, 9, 5)), now: now), '09:05');
    expect(messageTime(at(DateTime(2026, 10, 3, 14, 30)), now: now),
        '3 Oct 14:30');
    expect(
        messageTime(at(DateTime(2025, 1, 2, 8)), now: now), '2 Jan 2025 08:00');
  });

  test('the bridge JSON of a conversation parses', () {
    final messages = AssistantJson.parseConversationMessages(
        '[{"id":"m","author":"a","author_name":"Alice","mine":false,'
        '"text":null,"c":5}]');
    expect(messages.single.authorName, 'Alice');
    expect(messages.single.text, isNull);
    expect(messages.single.createdAt, 5);
  });
}
