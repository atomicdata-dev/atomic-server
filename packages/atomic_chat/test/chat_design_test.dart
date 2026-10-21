import 'package:atomic_chat/atomic_chat.dart';
import 'package:atomic_chat/src/chat_text_styles.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

/// The messenger look of direct messages and rooms: own messages right in the
/// accent colour, others' left in a hairline-edged neutral bubble with an
/// avatar at the end of a run, names only in groups, times only at the end of
/// a run, a compact header and a pill composer.
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

class _Api extends UnimplementedApi {
  final List<ConversationMessage> log;
  const _Api(this.log);

  @override
  Future<List<ConversationMessage>> conversationMessages(String s) async => log;
  @override
  Future<void> followConversation(String subject) async {}
}

double _ratio(Color a, Color b) {
  final l1 = a.computeLuminance(), l2 = b.computeLuminance();
  final hi = l1 > l2 ? l1 : l2, lo = l1 > l2 ? l2 : l1;
  return (hi + 0.05) / (lo + 0.05);
}

Future<void> _open(WidgetTester tester, List<ConversationMessage> log,
    {required AppColors colors,
    required double width,
    String title = 'Alice'}) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = Size(width, 900);
  addTearDown(tester.view.reset);
  await tester.pumpWidget(MaterialApp(
    theme: ThemeData(
        brightness:
            colors == AppColors.dark ? Brightness.dark : Brightness.light,
        extensions: [colors]),
    home: ConversationScreen(
        api: _Api(log), subject: 'did:ad:convo', title: title),
  ));
  await tester.pumpAndSettle();
}

Finder _sel(String t) =>
    find.byWidgetPredicate((w) => w is SelectableText && w.data == t);

Finder _bubbleOf(String text) => find.ancestor(
    of: find.text(text), matching: find.byKey(const Key('message-bubble')));

BoxDecoration _box(WidgetTester tester, String text) =>
    tester.widget<Container>(_bubbleOf(text)).decoration! as BoxDecoration;

void main() {
  final dm = [
    _msg('1', 'alice', 'one', _t0),
    _msg('2', 'alice', 'two', _t0 + _minute),
    _msg('3', 'me', 'three', _t0 + 2 * _minute, mine: true),
    _msg('4', 'alice', 'four', _t0 + 30 * _minute),
  ];

  for (final colors in [AppColors.light, AppColors.dark]) {
    for (final width in [393.0, 1200.0]) {
      final label = '${colors == AppColors.dark ? 'dark' : 'light'} $width';

      testWidgets('own right in the accent, others left with avatar ($label)',
          (tester) async {
        await _open(tester, dm, colors: colors, width: width);
        final list = tester.getRect(find.byType(ListView));
        final own = tester.getRect(_bubbleOf('three'));
        expect(own.right, closeTo(list.right - 12, 0.5));
        final other = tester.getRect(_bubbleOf('one'));
        // The 32 dp avatar slot and its 8 dp gap come first.
        expect(other.left, closeTo(list.left + 12 + 40, 0.5));
        expect(own.left, greaterThan(other.left));

        // Own: the main colour (deepened only if white would not read).
        final fill = _box(tester, 'three').color!;
        expect(fill, ChatTextStyles.ownBubble(colors));
        if (colors == AppColors.light) expect(fill, colors.main);
        expect(_ratio(fill, ChatTextStyles.onOwn), greaterThanOrEqualTo(4.5));
        expect(_box(tester, 'three').border, isNull);
        final ownText =
            tester.widget<SelectableText>(_sel('three')).style!.color;
        expect(ownText, ChatTextStyles.onOwn);

        // Others: neutral with a hairline that stands off the page.
        final o = _box(tester, 'one');
        expect(o.color, colors.bg1);
        final edge = (o.border! as Border).top;
        expect(edge.width, 1);
        final seen = Color.alphaBlend(edge.color, o.color!);
        expect(_ratio(seen, colors.bgBody), greaterThanOrEqualTo(1.2));
        expect(
            _ratio(tester.widget<SelectableText>(_sel('one')).style!.color!,
                colors.bg1),
            greaterThanOrEqualTo(4.5));

        // Width cap: 78% of the list, at most 640.
        expect(other.width, lessThanOrEqualTo(640));
        expect(own.width, lessThanOrEqualTo(list.width * 0.78 + 0.5));
      });

      testWidgets('runs: name, avatar and time ($label)', (tester) async {
        await _open(tester, dm, colors: colors, width: width);
        // A direct message names nobody.
        expect(find.byKey(const Key('message-author')), findsNothing);
        // The avatar sits on the last message of each run of the others.
        final avatars = find.byKey(const Key('message-avatar'));
        expect(avatars, findsNWidgets(2));
        final two = tester.getRect(_bubbleOf('two'));
        final one = tester.getRect(_bubbleOf('one'));
        final first = tester.getRect(avatars.first);
        final ys = [
          for (final e in avatars.evaluate())
            tester.getRect(find.byWidget(e.widget)).bottom
        ];
        expect(ys.any((y) => (y - two.bottom).abs() < 0.5), isTrue);
        expect(ys.any((y) => (y - one.bottom).abs() < 0.5), isFalse);
        expect(first.width, 32);
        // No avatar beside own messages: the avatars are left of the list.
        final list = tester.getRect(find.byType(ListView));
        for (final e in avatars.evaluate()) {
          expect(tester.getRect(find.byWidget(e.widget)).left,
              closeTo(list.left + 12, 0.5));
        }
        // Time: at the end of each run, not on every message.
        final times = find.byKey(const Key('message-time'));
        expect(times, findsNWidgets(3));
        expect(find.descendant(of: _bubbleOf('one'), matching: times),
            findsNothing);
        expect(find.descendant(of: _bubbleOf('two'), matching: times),
            findsOneWidget);
        expect(find.descendant(of: _bubbleOf('four'), matching: times),
            findsOneWidget);
        // A day separator opens the day.
        expect(find.byKey(const Key('day-separator')), findsOneWidget);
      });

      testWidgets(
          'a group names others once per run, in a readable colour ($label)',
          (tester) async {
        await _open(
            tester,
            [
              _msg('1', 'alice', 'one', _t0),
              _msg('2', 'alice', 'two', _t0 + _minute),
              _msg('3', 'bob', 'three', _t0 + 2 * _minute),
              _msg('4', 'me', 'four', _t0 + 3 * _minute, mine: true),
            ],
            colors: colors,
            width: width,
            title: 'Alice, Bob');
        final names = find.byKey(const Key('message-author'));
        expect(names, findsNWidgets(2));
        expect(find.descendant(of: _bubbleOf('two'), matching: names),
            findsNothing);
        for (final t in tester.widgetList<Text>(names)) {
          expect(_ratio(t.style!.color!, colors.bgBody),
              greaterThanOrEqualTo(4.5));
          expect(
              _ratio(t.style!.color!, colors.bg1), greaterThanOrEqualTo(4.5));
          expect(t.style!.fontSize, inInclusiveRange(12.5, 13));
        }
        expect(find.text('2 members'), findsNothing);
        expect(find.text('3 members'), findsOneWidget);
      });

      testWidgets(
          'header: avatar, name and subtitle hug the back arrow ($label)',
          (tester) async {
        await _open(tester, dm, colors: colors, width: width);
        final back = tester.getRect(find.byType(BackButton).evaluate().isEmpty
            ? find.byType(IconButton).first
            : find.byType(BackButton));
        final avatar =
            tester.getRect(find.byKey(const Key('chat-header-avatar')));
        final title =
            tester.getRect(find.byKey(const Key('chat-header-title')));
        expect(avatar.size, const Size(36, 36));
        expect(avatar.left - back.right, lessThanOrEqualTo(16));
        expect(title.left - avatar.right, lessThanOrEqualTo(16));
        expect(find.text('Direct message'), findsOneWidget);
        final sub = tester
            .widget<Text>(find.byKey(const Key('chat-header-subtitle')))
            .style!;
        expect(sub.fontSize, 12.5);
        expect(_ratio(sub.color!, colors.bgBody), greaterThanOrEqualTo(4.5));
      });

      testWidgets(
          'composer: pill, accent send with text, quiet when empty ($label)',
          (tester) async {
        await _open(tester, dm, colors: colors, width: width);
        final field = tester.getRect(find.byType(TextField));
        expect(field.height, greaterThanOrEqualTo(48));
        final deco =
            tester.widget<TextField>(find.byType(TextField)).decoration!;
        expect((deco.enabledBorder! as OutlineInputBorder).borderRadius,
            BorderRadius.circular(24));
        expect(deco.fillColor, colors.bg1);
        expect(deco.hintText, 'Message');

        ButtonStyle style() =>
            tester.widget<IconButton>(find.byType(IconButton).last).style!;
        final send = find.byTooltip('Send');
        expect(tester.getSize(send), const Size(44, 44));
        // Empty: disabled, quiet.
        expect(
            tester.widget<IconButton>(find.byType(IconButton).last).onPressed,
            isNull);
        expect(style().backgroundColor!.resolve({WidgetState.disabled}),
            colors.bg1);
        // With text: the accent, white arrow.
        await tester.enterText(find.byType(TextField), 'hello');
        await tester.pump(const Duration(milliseconds: 200));
        expect(
            tester.widget<IconButton>(find.byType(IconButton).last).onPressed,
            isNotNull);
        expect(style().backgroundColor!.resolve({}),
            ChatTextStyles.ownBubble(colors));
        expect(style().foregroundColor!.resolve({}), ChatTextStyles.onOwn);
      });
    }
  }

  test('own bubble keeps the dark theme main hue and reads with white', () {
    final dark = ChatTextStyles.ownBubble(AppColors.dark);
    expect(_ratio(dark, ChatTextStyles.onOwn), greaterThanOrEqualTo(4.5));
    expect(
        (HSLColor.fromColor(dark).hue -
                HSLColor.fromColor(AppColors.dark.main).hue)
            .abs(),
        lessThan(3));
    expect(HSLColor.fromColor(dark).lightness,
        lessThan(HSLColor.fromColor(AppColors.dark.main).lightness));
    for (final colors in [AppColors.light, AppColors.dark]) {
      // Time on an own bubble stays readable.
      final fill = ChatTextStyles.ownBubble(colors);
      expect(_ratio(Color.alphaBlend(ChatTextStyles.onOwnMuted, fill), fill),
          greaterThanOrEqualTo(4.5));
      for (final name in [
        'joep.io',
        'Polle Pas 1',
        'Alice',
        'Zed',
        'Yan',
        'Gus'
      ]) {
        final n = ChatTextStyles.nameColor(colors, name);
        expect(_ratio(n, colors.bgBody), greaterThanOrEqualTo(4.5));
        expect(_ratio(n, colors.bg1), greaterThanOrEqualTo(4.5));
        expect(ChatTextStyles.nameColor(colors, name), n);
      }
    }
  });

  testWidgets('grouped corners are small where a run joins', (tester) async {
    await _open(tester, dm, colors: AppColors.light, width: 393);
    BorderRadius r(String t) => _box(tester, t).borderRadius! as BorderRadius;
    // Others (joining side: left): first one has a small bottom-left.
    expect(r('one').bottomLeft.x, 6);
    expect(r('one').topLeft.x, 18);
    expect(r('two').topLeft.x, 6);
    expect(r('two').bottomLeft.x, 18);
    // Own, alone: all round. A lone other message too.
    expect(r('three').topRight.x, 18);
    expect(r('three').bottomRight.x, 18);
    expect(r('four').topLeft.x, 18);
  });
}
