import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;

/// The one set of chat type and bubble metrics, shared by the AI chat, chat
/// rooms, direct messages and their composers, so they read the same.
///
/// Sizes are logical pixels before the system text scale; [ChatTextScope]
/// keeps that scale between 1.0 and [maxTextScale].
class ChatTextStyles {
  /// Message text and the composer input.
  static const bodySize = 16.0;
  static const bodyHeight = 1.4;
  static const senderSize = 13.0;
  static const timeSize = 12.0;
  static const statusSize = 14.0;
  static const metaSize = 12.5;
  static const daySize = 13.0;
  static const quoteSize = 14.0;
  static const codeSize = 14.0;

  /// Markdown headings, h1 to h3.
  static const headingSizes = [22.0, 20.0, 18.0];

  /// The text scale above which chat text stops growing.
  static const maxTextScale = 1.6;

  /// Bubble box: padding, corner radius, share of the list width, and the
  /// cap that keeps lines short enough to read on a tablet.
  static const bubblePadding =
      EdgeInsets.symmetric(horizontal: 14, vertical: 10);
  static const bubbleRadius = 18.0;
  static const bubbleWidthFactor = 0.78;
  static const answerWidthFactor = 0.92;
  static const maxBubbleWidth = 640.0;

  /// Space between messages of one sender run, and between runs.
  static const runGap = 2.0;
  static const groupGap = 12.0;

  /// The list's side gutters and the avatar slot beside others' messages.
  static const gutter = 12.0;
  static const avatarSize = 32.0;
  static const avatarGap = 8.0;

  /// The corner a bubble keeps where it joins its neighbour in a run.
  static const joinRadius = 6.0;

  /// Text on the person's own (accent) bubbles.
  static const onOwn = Color(0xFFFFFFFF);

  final TextStyle body;
  final TextStyle bodyMine;
  final TextStyle sender;
  final TextStyle meta;
  final TextStyle time;
  final TextStyle daySeparator;
  final TextStyle quote;
  final TextStyle status;
  final TextStyle statusMono;
  final TextStyle composer;
  final TextStyle composerHint;

  const ChatTextStyles._({
    required this.body,
    required this.bodyMine,
    required this.sender,
    required this.meta,
    required this.time,
    required this.daySeparator,
    required this.quote,
    required this.status,
    required this.statusMono,
    required this.composer,
    required this.composerHint,
  });

  factory ChatTextStyles.from(AppColors c) {
    final body = TextStyle(
      color: c.textPrimary,
      fontSize: bodySize,
      height: bodyHeight,
    );
    return ChatTextStyles._(
      body: body,
      bodyMine: body.copyWith(color: onOwn),
      sender: TextStyle(
        color: c.textSecondary,
        fontSize: senderSize,
        fontWeight: FontWeight.w600,
        height: 1.3,
      ),
      meta: TextStyle(color: c.textSecondary, fontSize: metaSize, height: 1.3),
      time: TextStyle(color: c.textSecondary, fontSize: timeSize, height: 1.2),
      daySeparator: TextStyle(
        color: c.textSecondary,
        fontSize: daySize,
        fontWeight: FontWeight.w500,
        height: 1.3,
      ),
      quote: TextStyle(
        color: c.textSecondary,
        fontSize: quoteSize,
        height: bodyHeight,
      ),
      status:
          TextStyle(color: c.textSecondary, fontSize: statusSize, height: 1.3),
      statusMono: TextStyle(
        color: c.textSecondary,
        fontSize: 13,
        height: 1.35,
        fontFamily: 'monospace',
        fontFamilyFallback: const ['Menlo', 'Courier'],
      ),
      composer: body,
      composerHint: body.copyWith(color: c.textSecondary),
    );
  }

  static ChatTextStyles of(BuildContext context) =>
      ChatTextStyles.from(context.appColors);

  /// The widest a bubble may be in a list [listWidth] wide; [answer] bubbles
  /// (AI replies with code and tables) get more of it.
  static double bubbleMaxWidth(double listWidth, {bool answer = false}) =>
      math.min(
        listWidth * (answer ? answerWidthFactor : bubbleWidthFactor),
        maxBubbleWidth,
      );

  static bool _isDark(AppColors c) => c.bgBody.computeLuminance() < 0.5;

  static double _contrast(Color a, Color b) {
    final l1 = a.computeLuminance(), l2 = b.computeLuminance();
    final hi = math.max(l1, l2), lo = math.min(l1, l2);
    return (hi + 0.05) / (lo + 0.05);
  }

  /// The fill of the person's own bubbles: the main colour, deepened (in the
  /// dark theme's light main) just until white text on it reads at 4.5:1.
  static Color ownBubble(AppColors c) {
    var hsl = HSLColor.fromColor(c.main);
    var color = c.main;
    while (_contrast(onOwn, color) < 5.0 && hsl.lightness > 0.05) {
      hsl = hsl.withLightness(hsl.lightness - 0.01);
      color = hsl.toColor();
    }
    return color;
  }

  /// Time and state marks on an own bubble.
  static const onOwnMuted = Color(0xE6FFFFFF);

  /// The fill of others' bubbles.
  static Color otherBubble(AppColors c) => c.bg1;

  /// A hairline that shows on the page in both themes (bubble edges, the
  /// composer's field and top edge, the day pill).
  static Color hairline(AppColors c) => _isDark(c)
      ? const Color(0x24FFFFFF) // white 14%
      : const Color(0x1F000000); // black 12%

  /// A stable colour for a sender's name, readable (4.5:1) on the page and on
  /// others' bubbles.
  static Color nameColor(AppColors c, String name) {
    var h = 0;
    for (final r in name.trim().toLowerCase().runes) {
      h = (h * 31 + r) & 0x7fffffff;
    }
    final dark = _isDark(c);
    var hsl =
        HSLColor.fromAHSL(1, (h % 360).toDouble(), 0.6, dark ? 0.70 : 0.34);
    var color = hsl.toColor();
    // Yellows and greens are bright at any hue: step until it reads.
    var guard = 0;
    while ((_contrast(color, c.bgBody) < 4.6 ||
            _contrast(color, otherBubble(c)) < 4.6) &&
        guard++ < 40) {
      hsl = hsl.withLightness(
          (hsl.lightness + (dark ? 0.01 : -0.01)).clamp(0.0, 1.0));
      color = hsl.toColor();
    }
    return color;
  }

  /// The corners of a bubble: round, with the small [joinRadius] on the side
  /// of the sender's edge where it joins a message above or below.
  static BorderRadius bubbleCorners({
    required bool mine,
    required bool joinAbove,
    required bool joinBelow,
  }) {
    const big = Radius.circular(bubbleRadius);
    const small = Radius.circular(joinRadius);
    final top = joinAbove ? small : big;
    final bottom = joinBelow ? small : big;
    return mine
        ? BorderRadius.only(
            topLeft: big, bottomLeft: big, topRight: top, bottomRight: bottom)
        : BorderRadius.only(
            topRight: big, bottomRight: big, topLeft: top, bottomLeft: bottom);
  }

  /// The box of a bubble: accent for mine, a neutral hairline-edged one for
  /// the others.
  static BoxDecoration bubbleDecoration(
    AppColors c, {
    required bool mine,
    bool joinAbove = false,
    bool joinBelow = false,
  }) =>
      BoxDecoration(
        color: mine ? ownBubble(c) : otherBubble(c),
        border: mine ? null : Border.all(color: hairline(c)),
        borderRadius: bubbleCorners(
            mine: mine, joinAbove: joinAbove, joinBelow: joinBelow),
      );

  /// Space above a message: more where the sender changes.
  static double gapAbove(bool newRun) => newRun ? groupGap : runGap;
}

/// Keeps the system text scale from shrinking chat text below 1.0 or growing
/// it past [ChatTextStyles.maxTextScale], so bubbles and the composer hold.
class ChatTextScope extends StatelessWidget {
  final Widget child;
  const ChatTextScope({super.key, required this.child});

  @override
  Widget build(BuildContext context) => MediaQuery.withClampedTextScaling(
        minScaleFactor: 1,
        maxScaleFactor: ChatTextStyles.maxTextScale,
        child: child,
      );
}
