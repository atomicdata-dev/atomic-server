import 'package:flutter/material.dart';

export 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;

Color adjustColorForDarkMode(Color color, bool isDarkMode) {
  if (!isDarkMode) return color;
  final hsl = HSLColor.fromColor(color);
  return hsl.withLightness(1.0 - hsl.lightness).toColor();
}
