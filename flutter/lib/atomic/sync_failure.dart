/// A sync failure told in two layers: a [summary] a person can act on, and the
/// raw [details] lines (server URLs, exception text) kept for a "Details" panel
/// and for bug reports. The raw text never belongs on the main surface.
class SyncFailure {
  const SyncFailure({
    required this.title,
    required this.summary,
    required this.details,
  });

  final String title;
  final String summary;
  final List<String> details;

  static const _noDevice = 'No other device answered. Open the app on a '
      'device that has your drive and keep it on the same network.';

  /// The summary lines `sync_connectivity_now` puts first in its message.
  static const _hostSummaries = [
    _noDevice,
    'Could not look for your devices. Check your internet connection and try '
        'again.',
    'Could not reach your other devices.',
  ];

  /// Split a multi-line error report into a friendly summary plus the raw
  /// lines. Never returns raw exception text or URLs in [summary].
  static SyncFailure parse(String raw) {
    final details = raw
        .split('\n')
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty)
        .toList();
    const title = 'Couldn’t reach your devices';
    // The host (Rust) already leads with a plain summary line, then the raw
    // lines: take that as it is.
    for (final known in _hostSummaries) {
      if (details.isNotEmpty && details.first == known) {
        return SyncFailure(
          title: title,
          summary: known,
          details: details.skip(1).toList(),
        );
      }
    }
    final all = details.join('\n');
    String summary;
    if (RegExp(r'None of the \d+ devices?|timed out|No devices?',
            caseSensitive: false)
        .hasMatch(all)) {
      summary = _noDevice;
    } else if (RegExp(r'PanicException|CryptoProvider|Exception|Error',
            caseSensitive: false)
        .hasMatch(all)) {
      summary = 'Something went wrong while syncing. Try again in a moment.';
    } else if (RegExp(r'ClientConnection|SocketException|certificate|offline',
            caseSensitive: false)
        .hasMatch(all)) {
      summary = 'Couldn’t connect. Check your internet connection and try '
          'again.';
    } else if (details.isNotEmpty && !all.contains('://')) {
      // A plain-language line already (e.g. "Synced, but your workspace isn't
      // here yet"): show the last one, minus wrappers.
      summary =
          details.last.replaceAll(RegExp(r'PanicException\(?'), '').trim();
    } else {
      summary = _noDevice;
    }
    return SyncFailure(title: title, summary: summary, details: details);
  }
}
