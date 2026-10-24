import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Error text for a person: without Dart's exception prefixes ("Bad state: ",
/// "Exception: "), wherever they sit in a composed message. The one place
/// errors become text.
String cleanError(String message) => message.replaceAllMapped(
    RegExp(r'(^|: )(Bad state|Exception): '), (m) => m[1]!);

/// Show an error that does NOT auto-dismiss: it stays until the user taps it
/// away (the close icon) and offers a Copy button. A sync or pairing failure
/// that used to flash past for a second can now be read and copied for a bug
/// report.
void showErrorSnack(BuildContext context, String message) {
  final messenger = ScaffoldMessenger.of(context);
  final scheme = Theme.of(context).colorScheme;
  message = cleanError(message);

  // Replace any earlier error rather than stacking them.
  messenger.clearSnackBars();
  messenger.showSnackBar(
    SnackBar(
      content: Text(
        message,
        style: TextStyle(color: scheme.onInverseSurface),
      ),
      // Effectively persistent — dismissed by the close icon or Copy, not a
      // timer. (SnackBar has no true "forever", so use a long duration.)
      duration: const Duration(minutes: 10),
      showCloseIcon: true,
      // Opaque inverse surface: readable on light and dark, over any scrim.
      backgroundColor: scheme.inverseSurface,
      closeIconColor: scheme.onInverseSurface,
      behavior: SnackBarBehavior.floating,
      action: SnackBarAction(
        label: 'Copy',
        textColor: scheme.inversePrimary,
        onPressed: () {
          Clipboard.setData(ClipboardData(text: message));
        },
      ),
    ),
  );
}
