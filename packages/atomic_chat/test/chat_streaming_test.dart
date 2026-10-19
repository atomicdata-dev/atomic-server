import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

class _Api extends UnimplementedApi {
  _Api(this.ai, {this.addGate, this.history = const []});
  final HostedAi ai;
  final Future<void>? addGate;
  final List<ChatMessage> history;
  final added = <(String, String, String)>[];
  int messageReads = 0;

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<List<ChatMessage>> messages(String chat) async {
    messageReads++;
    return history;
  }

  @override
  Future<String> newChat(String name) async => 'did:ad:chat';
  @override
  Future<void> addMessage(String chat, String role, String text) async {
    await addGate;
    added.add((chat, role, text));
  }
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: home,
    );

HostedAi _ai(Stream<String> Function() stream, [void Function()? onCall]) =>
    HostedAi(
      status: {'enabled': true, 'consent': true, 'model': 'm'},
      stream: (messages, model) {
        onCall?.call();
        return stream();
      },
      enable: () async => {},
    );

Future<void> _type(WidgetTester tester, String text) async {
  await tester.enterText(find.byType(TextField), text);
  await tester.pump();
  await tester.tap(find.byTooltip('Send'));
  await tester.pump();
}

void main() {
  testWidgets(
      'a stop button replaces send while streaming; stopping keeps '
      'the partial text and frees the input', (tester) async {
    final controller = StreamController<String>();
    var cancelled = false;
    controller.onCancel = () => cancelled = true;
    final api = _Api(_ai(() => controller.stream));
    await tester.pumpWidget(_app(ChatScreen(api: api)));
    await tester.pumpAndSettle();

    await _type(tester, 'Hi');
    expect(find.byKey(const Key('chat-stop')), findsOneWidget);
    expect(find.byTooltip('Send'), findsNothing);

    controller.add('Hel');
    await tester.pump();
    controller.add('lo');
    await tester.pump(const Duration(milliseconds: 600));
    expect(find.byType(CircularProgressIndicator), findsNothing);

    await tester.tap(find.byKey(const Key('chat-stop')));
    await tester.pumpAndSettle();

    expect(cancelled, isTrue);
    expect(find.byKey(const Key('chat-stop')), findsNothing);
    expect(find.byTooltip('Send'), findsOneWidget);
    expect(find.text('Hello'), findsOneWidget);
    expect(api.added.last, ('did:ad:chat', 'assistant', 'Hello'));
    // Not re-read from the store after the answer.
    expect(api.messageReads, 0);
  });

  testWidgets('stopping before any text discards the empty answer',
      (tester) async {
    final controller = StreamController<String>();
    final api = _Api(_ai(() => controller.stream));
    await tester.pumpWidget(_app(ChatScreen(api: api)));
    await tester.pumpAndSettle();

    await _type(tester, 'Hi');
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    await tester.tap(find.byKey(const Key('chat-stop')));
    await tester.pumpAndSettle();

    expect(find.byType(CircularProgressIndicator), findsNothing);
    expect(api.added.map((a) => a.$2), ['user']);
    expect(find.byType(TextField), findsOneWidget);
  });

  testWidgets('the first delta renders before the stream completes',
      (tester) async {
    final controller = StreamController<String>();
    final api = _Api(_ai(() => controller.stream));
    await tester.pumpWidget(_app(ChatScreen(api: api)));
    await tester.pumpAndSettle();

    await _type(tester, 'Hi');
    controller.add('First words');
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    expect(find.textContaining('First'), findsWidgets);
    expect(find.byKey(const Key('chat-stop')), findsOneWidget);

    await controller.close();
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('chat-stop')), findsNothing);
  });

  testWidgets('the request does not wait for a slow addMessage',
      (tester) async {
    final gate = Completer<void>();
    var requested = 0;
    final api = _Api(
      _ai(() => Stream.value('Answer'), () => requested++),
      addGate: gate.future,
    );
    await tester.pumpWidget(_app(ChatScreen(api: api)));
    await tester.pumpAndSettle();

    await _type(tester, 'Hi');
    await tester.pump(const Duration(milliseconds: 50));
    expect(requested, 1);
    expect(api.added, isEmpty);
    expect(find.byKey(const Key('chat-stop')), findsNothing);

    gate.complete();
    await tester.pumpAndSettle();
    // Written in order: the user message, then the answer.
    expect(api.added.map((a) => a.$2), ['user', 'assistant']);
  });

  testWidgets('a long chat sends only its latest messages', (tester) async {
    List<Map<String, String>>? sent;
    final history = [
      for (var i = 0; i < 100; i++)
        (
          id: 'p#$i',
          role: i.isEven ? 'user' : 'assistant',
          text: 'm$i',
          createdAt: i
        ),
    ];
    final api = _Api(
      HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        stream: (messages, model) {
          sent = messages;
          return Stream.value('ok');
        },
        enable: () async => {},
      ),
      history: history,
    );
    await tester.pumpWidget(
        _app(ChatScreen(api: api, subject: 'did:ad:chat', title: 'Old')));
    await tester.pumpAndSettle();
    await _type(tester, 'again');
    await tester.pumpAndSettle();

    expect(sent!.length, HostedAi.maxHistoryMessages + 1);
    expect(sent!.last['content'], 'again');
  });
}
