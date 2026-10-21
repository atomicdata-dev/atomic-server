import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// "Show icons in the sidebar" (Appearance): the icons, pictures, emoji and
/// avatars in front of the Home list's rows. On by default.
///
/// One setting for the app and the web app inside it. The web app keeps it in
/// its own storage as `showSidebarIcons` (same default, same label); inside
/// the app the value lives here, per device, and goes both ways: the settings
/// page (embedded web) reports a change with the `sidebarIcons` call, and the
/// app passes the value to every page (`?sidebarIcons=` at load,
/// `atomicEmbed.setSidebarIcons` when it changes).
class AppSidebarIcons {
  AppSidebarIcons._();

  static final ValueNotifier<bool> show = ValueNotifier(true);

  /// SharedPreferences key.
  static const key = 'show_sidebar_icons';

  /// The saved choice, into [show].
  static Future<void> load() async {
    try {
      final p = await SharedPreferences.getInstance();
      show.value = p.getBool(key) ?? true;
    } catch (_) {}
  }

  /// A choice (from the page): shown at once, saved for the next start.
  static Future<void> choose(bool value) async {
    show.value = value;
    try {
      final p = await SharedPreferences.getInstance();
      await p.setBool(key, value);
    } catch (_) {}
  }

  /// The page's argument of the call: `[true]` or `[false]`.
  static bool? parse(Object? args) =>
      args is List && args.isNotEmpty && args.first is bool
          ? args.first as bool
          : null;

  /// The query parameter a page is loaded with.
  static String get queryValue => show.value ? '1' : '0';
}
