import 'package:flutter/material.dart';

@immutable
class AppColors extends ThemeExtension<AppColors> {
  /// Main canvas / scaffold background.
  final Color canvasBg;

  /// Toolbar, popup, and panel backgrounds.
  final Color panelBg;

  /// Subtle shadow color for panels and buttons.
  final Color panelShadow;

  /// Default icon / text color.
  final Color iconColor;

  /// Disabled icon color.
  final Color iconDisabled;

  /// Subtle border color on buttons and panels.
  final Color border;

  /// Width-indicator dot and progress bar fill.
  final Color dot;

  /// Card / tile surface.
  final Color surface;

  /// Empty / placeholder surface.
  final Color surfaceDim;

  /// Primary text.
  final Color textPrimary;

  /// Secondary / label text.
  final Color textSecondary;

  /// Fan overlay dim.
  final Color overlayDim;

  /// Hover shadow on buttons.
  final Color hoverShadow;

  /// Color-swatch border (non-selected).
  final Color swatchBorder;

  /// Width-picker selected-row highlight.
  final Color widthSelectedBg;

  /// Width preview stroke in fan.
  final Color widthPreviewStroke;

  /// Alert / warning background.
  final Color warningBg;

  /// Alert / warning border.
  final Color warningBorder;

  /// Error background.
  final Color errorBg;

  /// Gallery back-button background.
  final Color backButtonBg;

  // Tokens of the web app's `buildTheme` (browser/data-browser/src/styling.tsx),
  // with the main color #1b50d8 (dark: lightened by 0.2).

  /// Brand color (web `colors.main`).
  final Color main;

  /// Selected / own-message background (`mainSelectedBg`).
  final Color mainSelectedBg;

  /// Text on `mainSelectedBg` (`mainSelectedFg`).
  final Color mainSelectedFg;

  /// Page background of the assistant screens (`bgBody`).
  final Color bgBody;

  /// Raised surface, e.g. assistant message (`bg1`).
  final Color bg1;

  /// Strongest neutral surface (`bg2`).
  final Color bg2;

  /// Errors (`alert`).
  final Color alert;

  /// Confirmations, readable on `bgBody` (`success`).
  final Color success;

  const AppColors({
    required this.canvasBg,
    required this.panelBg,
    required this.panelShadow,
    required this.iconColor,
    required this.iconDisabled,
    required this.border,
    required this.dot,
    required this.surface,
    required this.surfaceDim,
    required this.textPrimary,
    required this.textSecondary,
    required this.overlayDim,
    required this.hoverShadow,
    required this.swatchBorder,
    required this.widthSelectedBg,
    required this.widthPreviewStroke,
    required this.warningBg,
    required this.warningBorder,
    required this.errorBg,
    required this.backButtonBg,
    required this.main,
    required this.mainSelectedBg,
    required this.mainSelectedFg,
    required this.bgBody,
    required this.bg1,
    required this.bg2,
    required this.alert,
    required this.success,
  });

  static const dark = AppColors(
    canvasBg: Colors.black,
    panelBg: Color(0xFF1A1A1A),
    panelShadow: Color(0x0FFFFFFF), // white 6%
    iconColor: Color(0xB3FFFFFF), // white70
    iconDisabled: Colors.grey,
    border: Color(0x1AFFFFFF), // white 10%
    dot: Color(0xFFD2D2D2),
    surface: Color(0xFF0A0A0A),
    surfaceDim: Color(0xFF111111),
    textPrimary: Color(0xFFE5E5E5),
    textSecondary: Color(0xFFAAAAAA),
    overlayDim: Color(0x66000000), // black 40%
    hoverShadow: Color(0x14FFFFFF), // white 8%
    swatchBorder: Color(0x3DFFFFFF), // white 24%
    widthSelectedBg: Color(0x660D47A1), // dark blue 40%
    widthPreviewStroke: Color(0x80FFFFFF), // white 50%
    warningBg: Color(0xFF3E2700),
    warningBorder: Color(0xFFE65100),
    errorBg: Color(0xFF3E0000),
    backButtonBg: Color(0xFF1A1A1A),
    main: Color(0xFF6C90ED),
    mainSelectedBg: Color(0xFF030817),
    mainSelectedFg: Color(0xFF7798EE),
    bgBody: Color(0xFF000000),
    bg1: Color(0xFF1A1A1A),
    bg2: Color(0xFF4D4D4D),
    alert: Color(0xFFCF5B5B),
    success: Color(0xFF4CC27A),
  );

  static const light = AppColors(
    canvasBg: Color(0xFFF5F5F5),
    panelBg: Color(0xFFFFFFFF),
    panelShadow: Color(0x1A000000),
    iconColor: Color(0xB3000000),
    iconDisabled: Colors.grey,
    border: Color(0x1A000000),
    dot: Color(0xFF666666),
    surface: Color(0xFFE0E0E0),
    surfaceDim: Color(0xFFCCCCCC),
    textPrimary: Color(0xFF111111),
    textSecondary: Color(0xFF666666),
    overlayDim: Color(0x33000000),
    hoverShadow: Color(0x14000000),
    swatchBorder: Color(0x3D000000),
    widthSelectedBg: Color(0x330D47A1),
    widthPreviewStroke: Color(0x80000000),
    warningBg: Color(0xFFFFF3E0),
    warningBorder: Color(0xFFFF9800),
    errorBg: Color(0xFFFFEBEE),
    backButtonBg: Color(0xFFFFFFFF),
    main: Color(0xFF1B50D8),
    mainSelectedBg: Color(0xFFF1F5FD),
    mainSelectedFg: Color(0xFF0E2A71),
    bgBody: Color(0xFFFAFAFA),
    bg1: Color(0xFFF2F2F2),
    bg2: Color(0xFFCCCCCC),
    alert: Color(0xFFCF5B5B),
    success: Color(0xFF237A42),
  );

  @override
  AppColors copyWith({
    Color? canvasBg,
    Color? panelBg,
    Color? panelShadow,
    Color? iconColor,
    Color? iconDisabled,
    Color? border,
    Color? dot,
    Color? surface,
    Color? surfaceDim,
    Color? textPrimary,
    Color? textSecondary,
    Color? overlayDim,
    Color? hoverShadow,
    Color? swatchBorder,
    Color? widthSelectedBg,
    Color? widthPreviewStroke,
    Color? warningBg,
    Color? warningBorder,
    Color? errorBg,
    Color? backButtonBg,
    Color? main,
    Color? mainSelectedBg,
    Color? mainSelectedFg,
    Color? bgBody,
    Color? bg1,
    Color? bg2,
    Color? alert,
    Color? success,
  }) {
    return AppColors(
      canvasBg: canvasBg ?? this.canvasBg,
      panelBg: panelBg ?? this.panelBg,
      panelShadow: panelShadow ?? this.panelShadow,
      iconColor: iconColor ?? this.iconColor,
      iconDisabled: iconDisabled ?? this.iconDisabled,
      border: border ?? this.border,
      dot: dot ?? this.dot,
      surface: surface ?? this.surface,
      surfaceDim: surfaceDim ?? this.surfaceDim,
      textPrimary: textPrimary ?? this.textPrimary,
      textSecondary: textSecondary ?? this.textSecondary,
      overlayDim: overlayDim ?? this.overlayDim,
      hoverShadow: hoverShadow ?? this.hoverShadow,
      swatchBorder: swatchBorder ?? this.swatchBorder,
      widthSelectedBg: widthSelectedBg ?? this.widthSelectedBg,
      widthPreviewStroke: widthPreviewStroke ?? this.widthPreviewStroke,
      warningBg: warningBg ?? this.warningBg,
      warningBorder: warningBorder ?? this.warningBorder,
      errorBg: errorBg ?? this.errorBg,
      backButtonBg: backButtonBg ?? this.backButtonBg,
      main: main ?? this.main,
      mainSelectedBg: mainSelectedBg ?? this.mainSelectedBg,
      mainSelectedFg: mainSelectedFg ?? this.mainSelectedFg,
      bgBody: bgBody ?? this.bgBody,
      bg1: bg1 ?? this.bg1,
      bg2: bg2 ?? this.bg2,
      alert: alert ?? this.alert,
      success: success ?? this.success,
    );
  }

  @override
  AppColors lerp(AppColors? other, double t) {
    if (other is! AppColors) return this;
    return AppColors(
      canvasBg: Color.lerp(canvasBg, other.canvasBg, t)!,
      panelBg: Color.lerp(panelBg, other.panelBg, t)!,
      panelShadow: Color.lerp(panelShadow, other.panelShadow, t)!,
      iconColor: Color.lerp(iconColor, other.iconColor, t)!,
      iconDisabled: Color.lerp(iconDisabled, other.iconDisabled, t)!,
      border: Color.lerp(border, other.border, t)!,
      dot: Color.lerp(dot, other.dot, t)!,
      surface: Color.lerp(surface, other.surface, t)!,
      surfaceDim: Color.lerp(surfaceDim, other.surfaceDim, t)!,
      textPrimary: Color.lerp(textPrimary, other.textPrimary, t)!,
      textSecondary: Color.lerp(textSecondary, other.textSecondary, t)!,
      overlayDim: Color.lerp(overlayDim, other.overlayDim, t)!,
      hoverShadow: Color.lerp(hoverShadow, other.hoverShadow, t)!,
      swatchBorder: Color.lerp(swatchBorder, other.swatchBorder, t)!,
      widthSelectedBg: Color.lerp(widthSelectedBg, other.widthSelectedBg, t)!,
      widthPreviewStroke:
          Color.lerp(widthPreviewStroke, other.widthPreviewStroke, t)!,
      warningBg: Color.lerp(warningBg, other.warningBg, t)!,
      warningBorder: Color.lerp(warningBorder, other.warningBorder, t)!,
      errorBg: Color.lerp(errorBg, other.errorBg, t)!,
      backButtonBg: Color.lerp(backButtonBg, other.backButtonBg, t)!,
      main: Color.lerp(main, other.main, t)!,
      mainSelectedBg: Color.lerp(mainSelectedBg, other.mainSelectedBg, t)!,
      mainSelectedFg: Color.lerp(mainSelectedFg, other.mainSelectedFg, t)!,
      bgBody: Color.lerp(bgBody, other.bgBody, t)!,
      bg1: Color.lerp(bg1, other.bg1, t)!,
      bg2: Color.lerp(bg2, other.bg2, t)!,
      alert: Color.lerp(alert, other.alert, t)!,
      success: Color.lerp(success, other.success, t)!,
    );
  }
}

/// Convenience getter — call from any widget with a BuildContext.
extension AppColorsExt on BuildContext {
  AppColors get appColors => Theme.of(this).extension<AppColors>()!;
}

Color adjustColorForDarkMode(Color color, bool isDarkMode) {
  if (!isDarkMode) return color;
  final hsl = HSLColor.fromColor(color);
  return hsl.withLightness(1.0 - hsl.lightness).toColor();
}
