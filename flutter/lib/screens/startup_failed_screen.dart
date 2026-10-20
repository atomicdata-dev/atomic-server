import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Shown instead of a black window when starting the app fails before there
/// is anything to show (the native library did not load or does not match the
/// Dart bindings, the documents directory is unavailable, ...). Plain on
/// purpose: it must not depend on anything that may be what failed.
class StartupFailedScreen extends StatefulWidget {
  const StartupFailedScreen({
    super.key,
    required this.error,
    required this.onRetry,
  });

  /// What went wrong, with the stack trace when there is one.
  final String error;

  /// Tries the start-up again; returns the new error, or null on success.
  final Future<String?> Function() onRetry;

  @override
  State<StartupFailedScreen> createState() => _StartupFailedScreenState();
}

class _StartupFailedScreenState extends State<StartupFailedScreen> {
  late String _error = widget.error;
  bool _retrying = false;
  bool _copied = false;

  Future<void> _retry() async {
    setState(() => _retrying = true);
    final error = await widget.onRetry();
    if (!mounted) return;
    setState(() {
      _retrying = false;
      if (error != null) _error = error;
    });
  }

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: _error));
    if (mounted) setState(() => _copied = true);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Icon(Icons.error_outline, size: 48, color: theme.colorScheme.error),
            const SizedBox(height: 16),
            Text('The app could not start',
                style: theme.textTheme.headlineSmall),
            const SizedBox(height: 12),
            Text(
              'Nothing was changed or deleted. Try again, or restart the app. '
              'If this keeps happening, copy the details and send them to us.',
              style: theme.textTheme.bodyLarge,
            ),
            const SizedBox(height: 24),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                FilledButton(
                  key: const Key('startup-retry'),
                  onPressed: _retrying ? null : _retry,
                  child: const Text('Try again'),
                ),
                OutlinedButton(
                  key: const Key('startup-copy'),
                  onPressed: _copy,
                  child: Text(_copied ? 'Copied' : 'Copy details'),
                ),
              ],
            ),
            const SizedBox(height: 16),
            SelectableText(_error, style: theme.textTheme.bodySmall),
          ],
        ),
      ),
    );
  }
}
