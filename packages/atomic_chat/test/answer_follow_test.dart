import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

/// How the AI chat follows an answer as it streams in: along at the bottom
/// while the answer's top is in view, then holding that top in place; never
/// against a person who scrolled; and on opening a chat whose last answer
/// is long, at that answer's start.
class _Api extends UnimplementedApi {
  _Api(this.ai, {this.history = const []});
  final HostedAi ai;
  final List<ChatMessage> history;

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<List<ChatMessage>> messages(String chat) async => history;
  @override
  Future<String> newChat(String name) async => 'did:ad:chat';
  @override
  Future<void> addMessage(String chat, String role, String text) async {}
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: home,
    );

HostedAi _ai(Stream<String> Function() stream) => HostedAi(
      status: {'enabled': true, 'consent': true, 'model': 'm'},
      stream: (messages, model) => stream(),
      enable: () async => {},
    );

Future<void> _send(WidgetTester tester, String text) async {
  await tester.enterText(find.byType(TextField), text);
  await tester.pump();
  await tester.tap(find.byTooltip('Send'));
  await tester.pump();
}

Finder _text(String t) => find.textContaining(t, findRichText: true);

/// The top of the chat list (below its padding).
double _listTop(WidgetTester tester) =>
    tester.getTopLeft(find.byType(ListView)).dy + 8;

double _listBottom(WidgetTester tester) =>
    tester.getBottomLeft(find.byType(ListView)).dy;

ScrollPosition _pos(WidgetTester tester) =>
    tester.state<ScrollableState>(find.byType(Scrollable).first).position;

/// Streams [lines] paragraphs, pumping past the screen's ~30 fps redraw.
Future<void> _stream(WidgetTester tester, StreamController<String> c,
    Iterable<int> lines) async {
  for (final i in lines) {
    c.add('Answer paragraph $i.\n\n');
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump();
  }
}

void main() {
  testWidgets('a short answer follows at the bottom, the question on top',
      (tester) async {
    final c = StreamController<String>();
    await tester.pumpWidget(_app(ChatScreen(api: _Api(_ai(() => c.stream)))));
    await tester.pumpAndSettle();
    await _send(tester, 'Short question');
    await _stream(tester, c, [0, 1]);
    // The question sits at the top, the answer under it, all in view.
    expect(tester.getTopLeft(_text('Short question')).dy,
        closeTo(_listTop(tester) + 38, 16));
    expect(tester.getBottomLeft(_text('Answer paragraph 1')).dy,
        lessThan(_listBottom(tester)));
    expect(_pos(tester).pixels, 0);
    await c.close();
    await tester.pumpAndSettle();
  });

  testWidgets('a tall answer stops scrolling once its top reaches the top',
      (tester) async {
    final c = StreamController<String>();
    await tester.pumpWidget(_app(ChatScreen(api: _Api(_ai(() => c.stream)))));
    await tester.pumpAndSettle();
    await _send(tester, 'Tall question');
    await _stream(tester, c, Iterable.generate(40, (i) => i));
    // The answer's first line is held at the top of the list; its end is
    // below the screen.
    final first = tester.getTopLeft(_text('Answer paragraph 0.')).dy;
    expect(first, greaterThanOrEqualTo(_listTop(tester) - 1));
    expect(first, lessThan(_listTop(tester) + 40));
    expect(tester.getTopLeft(_text('Answer paragraph 39')).dy,
        greaterThan(_listBottom(tester)),
        reason: 'the end is off screen, below');
    expect(_pos(tester).pixels, greaterThan(0));
    // More text keeps the start where it is.
    await _stream(tester, c, Iterable.generate(10, (i) => 40 + i));
    expect(tester.getTopLeft(_text('Answer paragraph 0.')).dy,
        moreOrLessEquals(first, epsilon: 1));
    await c.close();
    await tester.pumpAndSettle();
    expect(tester.getTopLeft(_text('Answer paragraph 0.')).dy,
        moreOrLessEquals(first, epsilon: 1));
  });

  testWidgets('scrolled away by hand, the answer no longer moves the screen',
      (tester) async {
    final c = StreamController<String>();
    await tester.pumpWidget(_app(ChatScreen(
        api: _Api(_ai(() => c.stream), history: [
          for (var i = 0; i < 30; i++)
            (
              id: 'h$i',
              role: i.isEven ? 'user' : 'assistant',
              text: 'Earlier message $i',
              createdAt: 1700000000000 + i * 1000
            ),
        ]),
        subject: 'did:ad:chat')));
    await tester.pumpAndSettle();
    await _send(tester, 'Question');
    await _stream(tester, c, [0, 1]);
    // Up by hand, to older messages.
    await tester.drag(find.byType(ListView), const Offset(0, 250));
    await tester.pumpAndSettle();
    final seen = find.textContaining('Earlier message', findRichText: true);
    final probe = seen.first;
    final at = tester.getTopLeft(probe).dy;
    await _stream(tester, c, Iterable.generate(20, (i) => 2 + i));
    expect(tester.getTopLeft(probe).dy, moreOrLessEquals(at, epsilon: 1));
    await c.close();
    await tester.pumpAndSettle();
  });

  testWidgets('a chat whose last answer is long opens at that answer\'s start',
      (tester) async {
    final long =
        [for (var i = 0; i < 60; i++) 'Long answer paragraph $i.'].join('\n\n');
    await tester.pumpWidget(_app(ChatScreen(
        api: _Api(_ai(() => const Stream.empty()), history: [
          (id: 'q', role: 'user', text: 'Tell me a lot', createdAt: 1),
          (id: 'a', role: 'assistant', text: long, createdAt: 2),
        ]),
        subject: 'did:ad:chat')));
    await tester.pumpAndSettle();
    expect(tester.getTopLeft(_text('Long answer paragraph 0.')).dy,
        moreOrLessEquals(_listTop(tester) + 32, epsilon: 12));
    expect(tester.getTopLeft(_text('Long answer paragraph 59')).dy,
        greaterThan(_listBottom(tester)));
  });

  testWidgets('a chat whose last answer is short opens at the bottom',
      (tester) async {
    await tester.pumpWidget(_app(ChatScreen(
        api: _Api(_ai(() => const Stream.empty()), history: [
          (id: 'q', role: 'user', text: 'Hi', createdAt: 1),
          (id: 'a', role: 'assistant', text: 'Hello there', createdAt: 2),
        ]),
        subject: 'did:ad:chat')));
    await tester.pumpAndSettle();
    expect(_pos(tester).pixels, 0);
    expect(_text('Hello there'), findsOneWidget);
  });

  testWidgets('a new section of the answer does not move the bubble for a frame',
      (tester) async {
    final c = StreamController<String>();
    await tester.pumpWidget(_app(ChatScreen(api: _Api(_ai(() => c.stream)))));
    await tester.pumpAndSettle();
    await _send(tester, 'Frame question');
    await _stream(tester, c, [0]);
    final question = tester.getTopLeft(_text('Frame question')).dy;
    final answer = tester.getTopLeft(_text('Answer paragraph 0.')).dy;
    // One frame at a time: the question and the answer's start stay put
    // in every frame, also the one in which a section is added.
    for (var i = 1; i < 6; i++) {
      c.add('Answer paragraph $i.\n\n');
      for (var f = 0; f < 4; f++) {
        await tester.pump(const Duration(milliseconds: 20));
        expect(tester.getTopLeft(_text('Frame question')).dy,
            moreOrLessEquals(question, epsilon: 0.5),
            reason: 'section $i, frame $f');
        expect(tester.getTopLeft(_text('Answer paragraph 0.')).dy,
            moreOrLessEquals(answer, epsilon: 0.5),
            reason: 'section $i, frame $f');
      }
    }
    await c.close();
    await tester.pumpAndSettle();
  });
}
