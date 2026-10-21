import 'package:atomic_flutter/atomic_flutter.dart' show showErrorSnack;
import 'package:flutter/material.dart';

/// What happened to a local store that could not be opened, as the bridge's
/// `store_recovery` reports it.
class StoreRecoveryNotice {
  const StoreRecoveryNotice({
    required this.keptPath,
    required this.reason,
    required this.repaired,
  });

  /// The damaged file, kept next to the new store for a bug report.
  final String keptPath;

  /// redb's error, shown folded away.
  final String reason;

  /// A repaired copy is in use (the last moments before the crash may be
  /// missing); otherwise the app starts on an empty store.
  final bool repaired;
}

/// Shown once, before anything else, when the app's local data could not be
/// opened. The broken file is never deleted: it stays on the device and can
/// be shared for debugging.
class StoreRecoveryScreen extends StatefulWidget {
  const StoreRecoveryScreen({
    super.key,
    required this.notice,
    required this.onContinue,
    required this.onShare,
  });

  final StoreRecoveryNotice notice;
  final VoidCallback onContinue;
  final Future<void> Function(String path) onShare;

  @override
  State<StoreRecoveryScreen> createState() => _StoreRecoveryScreenState();
}

class _StoreRecoveryScreenState extends State<StoreRecoveryScreen> {
  bool _sharing = false;

  Future<void> _share() async {
    setState(() => _sharing = true);
    try {
      await widget.onShare(widget.notice.keptPath);
    } catch (e) {
      if (mounted) {
        showErrorSnack(context, 'Could not share the file: $e');
      }
    } finally {
      if (mounted) setState(() => _sharing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final notice = widget.notice;
    final theme = Theme.of(context);
    final title = notice.repaired
        ? 'Your local data was repaired'
        : 'Your local data could not be opened';
    final body = notice.repaired
        ? 'The app was closed while it was saving, and the data on this '
            'device was damaged. It has been repaired; the last changes '
            'before the app closed may be missing. Changes that reached a '
            'server or a paired device come back when they sync.'
        : 'The app was closed while it was saving, and the data on this '
            'device was damaged beyond repair. The app starts with an empty '
            'local copy. Your identity is kept, so you stay signed in, and '
            'your drives come back from your server or paired devices when '
            'they sync. Anything that only existed on this device is in the '
            'damaged file, which is kept.';
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Icon(
              notice.repaired ? Icons.healing : Icons.report_problem_outlined,
              size: 48,
              color: theme.colorScheme.primary,
            ),
            const SizedBox(height: 16),
            Text(title, style: theme.textTheme.headlineSmall),
            const SizedBox(height: 12),
            Text(body, style: theme.textTheme.bodyLarge),
            const SizedBox(height: 24),
            FilledButton(
              key: const Key('store-recovery-continue'),
              onPressed: widget.onContinue,
              child: Text(notice.repaired ? 'Continue' : 'Start fresh'),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              key: const Key('store-recovery-share'),
              onPressed: _sharing ? null : _share,
              icon: const Icon(Icons.ios_share),
              label: const Text('Share the damaged file'),
            ),
            const SizedBox(height: 16),
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: const Text('Details'),
              children: [
                SelectableText(
                  '${notice.reason}\n\nKept at ${notice.keptPath}',
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// Shown when the local data could not be opened at all and nothing was
/// changed (a permission problem, a full disk): say so and offer to retry,
/// instead of a black screen.
class StoreOpenFailedScreen extends StatefulWidget {
  const StoreOpenFailedScreen({
    super.key,
    required this.error,
    required this.onRetry,
  });

  final String error;

  /// Tries again; returns the new error, or null once the store opened.
  final Future<String?> Function() onRetry;

  @override
  State<StoreOpenFailedScreen> createState() => _StoreOpenFailedScreenState();
}

class _StoreOpenFailedScreenState extends State<StoreOpenFailedScreen> {
  late String _error = widget.error;
  bool _retrying = false;

  Future<void> _retry() async {
    setState(() => _retrying = true);
    final error = await widget.onRetry();
    if (!mounted) return;
    setState(() {
      _retrying = false;
      if (error != null) _error = error;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Icon(Icons.storage, size: 48, color: theme.colorScheme.error),
            const SizedBox(height: 16),
            Text('The app could not open its local data',
                style: theme.textTheme.headlineSmall),
            const SizedBox(height: 12),
            Text(
              storeErrorAdvice(_error),
              style: theme.textTheme.bodyLarge,
            ),
            const SizedBox(height: 24),
            FilledButton(
              key: const Key('store-open-retry'),
              onPressed: _retrying ? null : _retry,
              child: const Text('Try again'),
            ),
            const SizedBox(height: 16),
            SelectableText(_error, style: theme.textTheme.bodySmall),
          ],
        ),
      ),
    );
  }
}

/// What to tell the person for a store that did not open: a denied write is
/// not a full disk, and the advice differs.
String storeErrorAdvice(String error) {
  final denied = RegExp('Operation not permitted|Permission denied',
          caseSensitive: false)
      .hasMatch(error);
  if (denied) {
    return "The app isn't allowed to write its data folder. Nothing was "
        'changed or deleted. Check the folder\'s permissions, then try again.';
  }
  return 'Nothing was changed or deleted. This can happen when the '
      'device is out of storage. Free some space and try again, or '
      'restart the app.';
}
