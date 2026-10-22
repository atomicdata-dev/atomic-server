import 'package:flutter/material.dart';

/// Press, hover and focus feedback without Material's expanding ink: a flat
/// tint of [ink] (the text colour) and a pointer over every enabled control.
/// Apply to the `ThemeData` of every `MaterialApp` and nested `Theme`.
ThemeData withCalmInteraction(ThemeData base, {required Color ink}) {
  final dark = base.brightness == Brightness.dark;
  final pressed = ink.withValues(alpha: dark ? 0.10 : 0.08);
  final hovered = ink.withValues(alpha: dark ? 0.06 : 0.05);
  final focused = ink.withValues(alpha: dark ? 0.10 : 0.08);

  final overlay = WidgetStateProperty.resolveWith<Color?>((s) {
    if (s.contains(WidgetState.pressed)) return pressed;
    if (s.contains(WidgetState.focused)) return focused;
    if (s.contains(WidgetState.hovered)) return hovered;
    return Colors.transparent;
  });
  final cursor = WidgetStateProperty.resolveWith<MouseCursor?>((s) =>
      s.contains(WidgetState.disabled)
          ? SystemMouseCursors.basic
          : SystemMouseCursors.click);

  ButtonStyle style() => ButtonStyle(
        splashFactory: NoSplash.splashFactory,
        overlayColor: overlay,
        mouseCursor: cursor,
      );

  return base.copyWith(
    splashFactory: NoSplash.splashFactory,
    splashColor: Colors.transparent,
    highlightColor: pressed,
    hoverColor: hovered,
    focusColor: focused,
    filledButtonTheme: FilledButtonThemeData(style: style()),
    outlinedButtonTheme: OutlinedButtonThemeData(style: style()),
    textButtonTheme: TextButtonThemeData(style: style()),
    elevatedButtonTheme: ElevatedButtonThemeData(style: style()),
    iconButtonTheme: IconButtonThemeData(style: style()),
    segmentedButtonTheme: SegmentedButtonThemeData(style: style()),
    menuButtonTheme: MenuButtonThemeData(style: style()),
    listTileTheme: base.listTileTheme.copyWith(mouseCursor: cursor),
    switchTheme: base.switchTheme.copyWith(
      mouseCursor: cursor,
      overlayColor: overlay,
    ),
    checkboxTheme: base.checkboxTheme.copyWith(
      mouseCursor: cursor,
      overlayColor: overlay,
      splashRadius: 0,
    ),
    radioTheme: base.radioTheme.copyWith(
      mouseCursor: cursor,
      overlayColor: overlay,
      splashRadius: 0,
    ),
    popupMenuTheme: base.popupMenuTheme.copyWith(mouseCursor: cursor),
  );
}
