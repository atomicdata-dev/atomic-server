import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

class _Api extends UnimplementedApi {
  _Api(this.ai);
  final HostedAi ai;
  final store = <ChatMessage>[];
  int failWrites = 0;
  int attempts = 0;

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<List<ChatMessage>> messages(String chat) async => List.of(store);
  @override
  Future<String> newChat(String name) async => 'did:ad:chat';
  @override
  Future<void> addMessage(String chat, String role, String text) async {
    attempts++;
    if (role == 'assistant' && failWrites > 0) {
      failWrites--;
      throw StateError('disk full');
    }
    store.add((
      id: 'm${store.length}',
      role: role,
      text: text,
      createdAt: store.length + 1,
    ));
  }
}

HostedAi _ai(Stream<String> Function() s) => HostedAi(
      status: {'enabled': true, 'consent': true, 'model': 'm'},
      stream: (m, model) => s(),
      enable: () async => {},
    );

Widget _app(Widget home, [ToastController? toasts]) {
  final app = MaterialApp(
    theme: ThemeData(extensions: [AppColors.light]),
    home: home,
  );
  return toasts == null ? app : ToastScope(controller: toasts, child: app);
}

Future<void> _send(WidgetTester tester, String text) async {
  await tester.enterText(find.byType(TextField), text);
  await tester.pump();
  await tester.tap(find.byTooltip('Send'));
  await tester.pump();
}

void main() {
  testWidgets('leaving the screen mid-answer does not lose the answer',
      (tester) async {
    final c = StreamController<String>();
    final api = _Api(_ai(() => c.stream));
    await tester.pumpWidget(_app(ChatScreen(api: api)));
    await tester.pumpAndSettle();
    await _send(tester, 'Hi');
    c.add('Hello ');
    await tester.pump(const Duration(milliseconds: 100));

    // Home: the chat screen is gone.
    await tester.pumpWidget(_app(const SizedBox()));
    c.add('world');
    await c.close();
    await tester.pumpAndSettle();

    expect(api.store.map((m) => (m.role, m.text)),
        [('user', 'Hi'), ('assistant', 'Hello world')]);

    // Opened again: the full answer is there.
    await tester.pumpWidget(_app(ChatScreen(api: api, subject: 'did:ad:chat')));
    await tester.pumpAndSettle();
    expect(find.textContaining('Hello world'), findsOneWidget);
  });

  testWidgets('reopening while the answer runs shows it live, then saved',
      (tester) async {
    final c = StreamController<String>();
    final api = _Api(_ai(() => c.stream));
    await tester.pumpWidget(_app(ChatScreen(api: api)));
    await tester.pumpAndSettle();
    await _send(tester, 'Hi');
    c.add('Part one');
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpWidget(_app(const SizedBox()));
    await tester.pump(const Duration(milliseconds: 100));

    await tester.pumpWidget(_app(ChatScreen(api: api, subject: 'did:ad:chat')));
    await tester.pumpAndSettle();
    expect(find.textContaining('Part one'), findsOneWidget);

    c.add(' and two');
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.textContaining('Part one and two'), findsOneWidget);
    await c.close();
    await tester.pumpAndSettle();
    expect(find.textContaining('Part one and two'), findsOneWidget);
    expect(api.store.last.text, 'Part one and two');
  });

  testWidgets('leaving right after the final chunk still saves it',
      (tester) async {
    final c = StreamController<String>();
    final api = _Api(_ai(() => c.stream));
    await tester.pumpWidget(_app(ChatScreen(api: api)));
    await tester.pumpAndSettle();
    await _send(tester, 'Hi');
    c.add('Done.');
    await c.close();
    // No frame for the 33 ms flush: leave at once.
    await tester.pumpWidget(_app(const SizedBox()));
    await tester.pumpAndSettle();
    expect(api.store.last.text, 'Done.');
  });

  testWidgets('a failing write is retried and the person is told',
      (tester) async {
    final toasts = ToastController();
    final api = _Api(_ai(() => Stream.value('Answer')))..failWrites = 2;
    await tester.pumpWidget(_app(ChatScreen(api: api), toasts));
    await tester.pumpAndSettle();
    await _send(tester, 'Hi');
    await tester.pump(const Duration(milliseconds: 100));
    expect(toasts.toasts.map((t) => t.message),
        contains("Couldn't save the answer, retrying"));
    await tester.pump(const Duration(seconds: 10));
    await tester.pumpAndSettle();
    expect(api.store.last.text, 'Answer');
    expect(toasts.toasts, isEmpty);
  });
}
