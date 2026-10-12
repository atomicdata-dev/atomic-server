import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Show an error that does NOT auto-dismiss: it stays until the user taps it
/// away (the close icon) and offers a Copy button. A sync or pairing failure
/// that used to flash past for a second can now be read and copied for a bug
/// report.
void showErrorSnack(BuildContext context, String message) {
  final messenger = ScaffoldMessenger.of(context);
  final theme = Theme.of(context);

  // Replace any earlier error rather than stacking them.
  messenger.clearSnackBars();
  messenger.showSnackBar(
    SnackBar(
      content: Text(
        message,
        style: TextStyle(color: theme.colorScheme.onErrorContainer),
      ),
      // Effectively persistent — dismissed by the close icon or Copy, not a
      // timer. (SnackBar has no true "forever", so use a long duration.)
      duration: const Duration(minutes: 10),
      showCloseIcon: true,
      backgroundColor: theme.colorScheme.errorContainer,
      closeIconColor: theme.colorScheme.onErrorContainer,
      behavior: SnackBarBehavior.floating,
      action: SnackBarAction(
        label: 'Copy',
        textColor: theme.colorScheme.onErrorContainer,
        onPressed: () {
          Clipboard.setData(ClipboardData(text: message));
        },
      ),
    ),
  );
}
