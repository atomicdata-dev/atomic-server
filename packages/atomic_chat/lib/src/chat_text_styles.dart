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
  static const senderSize = 14.0;
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
  static const runGap = 4.0;
  static const groupGap = 12.0;

  final TextStyle body;
  final TextStyle bodyMine;
  final TextStyle sender;
  final TextStyle meta;
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
      bodyMine: body.copyWith(color: c.mainSelectedFg),
      sender: TextStyle(
        color: c.textSecondary,
        fontSize: senderSize,
        fontWeight: FontWeight.w600,
        height: 1.3,
      ),
      meta: TextStyle(color: c.textSecondary, fontSize: metaSize, height: 1.3),
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
