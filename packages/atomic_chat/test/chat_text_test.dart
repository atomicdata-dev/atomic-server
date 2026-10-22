import 'package:atomic_chat/atomic_chat.dart';
import 'package:atomic_chat/src/chat_text_styles.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

/// The chat type is one shared set: the same readable sizes in the AI chat,
/// chat rooms and conversations, and bubbles that hold long lines to a
/// readable width.
const _t0 = 1700000000000;
final _long = List.filled(40, 'wrapping words').join(' ');

class _Api extends UnimplementedApi {
  final List<ChatMessage> history;
  final List<ChatRoomMessage> room;
  final List<ConversationMessage> convo;
  const _Api(
      {this.history = const [], this.room = const [], this.convo = const []});

  @override
  Future<HostedAi?> hostedAi() async => HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        stream: (messages, model) => const Stream.empty(),
        enable: () async => {},
      );
  @override
  Future<void> followConversation(String subject) async {}
  @override
  Future<List<ChatMessage>> messages(String chat) async => history;
  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String s) async => room;
  @override
  Future<List<ConversationMessage>> conversationMessages(String s) async =>
      convo;
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: home,
    );

ChatRoomMessage _room(String id, String who, String text, int at,
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

ConversationMessage _dm(String id, String who, String text, int at,
        {bool mine = false}) =>
    (
      id: id,
      author: 'did:ad:agent:$who',
      authorName: who,
      mine: mine,
      text: text,
      createdAt: at,
    );

/// The font size a text is drawn with.
double _size(WidgetTester tester, Finder f) {
  final p = tester.renderObject<RenderParagraph>(f);
  return p.text.style?.fontSize ??
      DefaultTextStyle.of(tester.element(f)).style.fontSize!;
}

Finder _sel(String t) => find.byWidgetPredicate(
    (w) => w is SelectableText && (w.data ?? '').startsWith(t),
    skipOffstage: false);

double _selSize(WidgetTester tester, Finder f) =>
    tester.widget<SelectableText>(f).style!.fontSize!;

double _fieldSize(WidgetTester tester) =>
    tester.widget<TextField>(find.byType(TextField)).style!.fontSize!;

double _textWidth(WidgetTester tester, Finder f) => tester.getSize(f).width;

void _view(WidgetTester tester, double width) {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = Size(width, 2400);
  addTearDown(tester.view.reset);
}

Finder _rich(String t) => find.descendant(
    of: find.byType(ListView),
    matching: find.textContaining(t, findRichText: true));

void main() {
  for (final width in [393.0, 1200.0]) {
    final label = width < 600 ? 'phone' : 'tablet';
    // The widest a message's text can be: the bubble less its padding.
    double cap({bool answer = false}) =>
        ChatTextStyles.bubbleMaxWidth(width - 24, answer: answer) - 28;

    testWidgets('AI chat text is readable and wraps ($label)', (tester) async {
      _view(tester, width);
      await tester.pumpWidget(_app(ChatScreen(
          api: _Api(history: [
            (id: 'a', role: 'user', text: 'Question $_long', createdAt: _t0),
            (
              id: 'b',
              role: 'assistant',
              text: 'Answer $_long',
              createdAt: _t0 + 1000
            ),
          ]),
          subject: 'did:ad:chat')));
      await tester.pumpAndSettle();
      final user = _rich('Question');
      final answer = _rich('Answer');
      expect(_size(tester, user), greaterThanOrEqualTo(16));
      expect(_size(tester, answer), greaterThanOrEqualTo(16));
      expect(_fieldSize(tester), greaterThanOrEqualTo(16));
      expect(tester.getSize(user).height, greaterThan(60), reason: 'wraps');
      expect(_textWidth(tester, user), lessThanOrEqualTo(cap()));
      expect(_textWidth(tester, answer), lessThanOrEqualTo(cap(answer: true)));
      final day = find.byKey(const Key('day-separator'));
      expect(_size(tester, day), greaterThanOrEqualTo(12.5));
    });

    testWidgets('chat room text is readable and wraps ($label)',
        (tester) async {
      _view(tester, width);
      await tester.pumpWidget(_app(ChatRoomScreen(
          api: _Api(room: [
            _room('1', 'Alice', 'Hello $_long', _t0),
            _room('2', 'me', 'Mine $_long', _t0 + 1000, mine: true),
          ]),
          drive: 'did:ad:drive',
          subject: 'did:ad:room')));
      await tester.pumpAndSettle();
      for (final t in ['Hello', 'Mine']) {
        final f = _sel(t);
        expect(_selSize(tester, f), greaterThanOrEqualTo(16));
        expect(tester.getSize(f).height, greaterThan(60), reason: 'wraps');
        expect(_textWidth(tester, f),
            lessThanOrEqualTo(cap()));
      }
      expect(_fieldSize(tester), greaterThanOrEqualTo(16));
      expect(_size(tester, find.byKey(const Key('message-time')).first),
          greaterThanOrEqualTo(12));
      expect(_size(tester, find.byKey(const Key('message-author'))),
          greaterThanOrEqualTo(12.5));
      expect(_size(tester, find.byKey(const Key('day-separator'))),
          greaterThanOrEqualTo(12.5));
    });

    testWidgets('conversation text is readable and wraps ($label)',
        (tester) async {
      _view(tester, width);
      await tester.pumpWidget(_app(ConversationScreen(
          api: _Api(convo: [
            _dm('1', 'alice', 'Hello $_long', _t0),
            _dm('2', 'bob', 'Hi $_long', _t0 + 1000),
            _dm('3', 'me', 'Mine $_long', _t0 + 2000, mine: true),
          ]),
          subject: 'did:ad:convo')));
      await tester.pumpAndSettle();
      for (final t in ['Hello', 'Mine']) {
        final f = _sel(t);
        expect(_selSize(tester, f), greaterThanOrEqualTo(16));
        expect(tester.getSize(f).height, greaterThan(60), reason: 'wraps');
        expect(_textWidth(tester, f), lessThanOrEqualTo(cap()));
      }
      expect(_fieldSize(tester), greaterThanOrEqualTo(16));
      expect(_size(tester, find.byKey(const Key('message-time')).first),
          greaterThanOrEqualTo(12));
      expect(_size(tester, find.byKey(const Key('message-author')).first),
          greaterThanOrEqualTo(12.5));
    });
  }

  testWidgets('the system text scale is kept between 1.0 and 1.6',
      (tester) async {
    late double seen;
    for (final (asked, want) in [(0.8, 1.0), (1.3, 1.3), (2.5, 1.6)]) {
      await tester.pumpWidget(MediaQuery(
        data: MediaQueryData(textScaler: TextScaler.linear(asked)),
        child: ChatTextScope(
          child: Builder(builder: (context) {
            seen = MediaQuery.textScalerOf(context).scale(10) / 10;
            return const SizedBox();
          }),
        ),
      ));
      expect(seen, closeTo(want, 0.001));
    }
  });

  test('the shared style set meets the minimum sizes and contrast', () {
    for (final colors in [AppColors.light, AppColors.dark]) {
      final s = ChatTextStyles.from(colors);
      expect(s.body.fontSize, greaterThanOrEqualTo(16));
      expect(s.body.height, 1.4);
      expect(s.composer.fontSize, greaterThanOrEqualTo(16));
      expect(s.sender.fontSize, inInclusiveRange(12.5, 13));
      expect(s.sender.fontWeight, FontWeight.w600);
      expect(s.meta.fontSize, inInclusiveRange(12, 12.5));
      expect(s.daySeparator.fontSize, inInclusiveRange(12.5, 13));
      expect(s.quote.fontSize, 14);
      double ratio(Color a, Color b) {
        final l1 = a.computeLuminance(), l2 = b.computeLuminance();
        final hi = l1 > l2 ? l1 : l2, lo = l1 > l2 ? l2 : l1;
        return (hi + 0.05) / (lo + 0.05);
      }

      expect(ratio(s.meta.color!, colors.bg1), greaterThanOrEqualTo(4.5));
      expect(ratio(s.meta.color!, colors.bgBody), greaterThanOrEqualTo(4.5));
    }
  });
}
