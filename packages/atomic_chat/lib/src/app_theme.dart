import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The person's light/dark choice for the whole app, made on the settings
/// page (the embedded web page's Theme: Auto, Dark, Light). The host app's
/// `MaterialApp` listens to [mode]; without a choice the app follows the
/// system. Saved per device.
class AppThemeMode {
  AppThemeMode._();

  static final ValueNotifier<ThemeMode> mode = ValueNotifier(ThemeMode.system);

  /// SharedPreferences key.
  static const key = 'app_theme_mode';

  /// The page's name of a choice ('auto', 'dark', 'light'), null for anything
  /// else.
  static ThemeMode? parse(Object? name) => switch (name) {
        'auto' => ThemeMode.system,
        'dark' => ThemeMode.dark,
        'light' => ThemeMode.light,
        _ => null,
      };

  /// The saved choice, into [mode].
  static Future<void> load() async {
    try {
      final p = await SharedPreferences.getInstance();
      mode.value = parse(p.getString(key)) ?? ThemeMode.system;
    } catch (_) {}
  }

  /// A choice from the page: shown at once, saved for the next start.
  static Future<void> choose(String name) async {
    final chosen = parse(name);
    if (chosen == null) return;
    mode.value = chosen;
    try {
      final p = await SharedPreferences.getInstance();
      await p.setString(key, name);
    } catch (_) {}
  }
}
