import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Connect this app to a hosted account, as the web app does: a short code is
/// shown, approved at the account's `/link` page on a device where the person
/// is signed in, and the token that comes back is saved. Nothing else changes:
/// the identity stays the one this device holds.
///
/// Pops with true when linked. [save] receives the session to keep.
class AccountLinkDialog extends StatefulWidget {
  final shared.AtomicAccountClient client;
  final String deviceName;
  final Future<void> Function(String session) save;

  /// Opens the approval page in the system browser, where the sign-in (an
  /// emailed link, a passkey) can finish; an in-app page cannot receive it.
  final Future<void> Function(Uri url)? openInBrowser;

  /// Ask the browser to send the account's identity to this app instead of
  /// only approving the device: the page is the web app's `send-identity`.
  final bool handback;

  const AccountLinkDialog({
    super.key,
    required this.client,
    required this.deviceName,
    required this.save,
    this.openInBrowser,
    this.handback = false,
  });

  @override
  State<AccountLinkDialog> createState() => _AccountLinkDialogState();
}

class _AccountLinkDialogState extends State<AccountLinkDialog> {
  shared.AtomicDeviceLink? _request;
  String? _error;
  Timer? _timer;
  int _generation = 0;

  @override
  void initState() {
    super.initState();
    _start();
  }

  @override
  void dispose() {
    _generation++;
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _start() async {
    _timer?.cancel();
    final generation = ++_generation;
    setState(() {
      _request = null;
      _error = null;
    });
    try {
      final request = await widget.client
          .requestLink(widget.deviceName, handback: widget.handback);
      if (!mounted || generation != _generation) return;
      setState(() => _request = request);
      _timer = Timer(request.interval, () => _poll(request, generation));
    } catch (e) {
      if (mounted && generation == _generation) {
        setState(() => _error = _friendly(e));
      }
    }
  }

  Future<void> _poll(shared.AtomicDeviceLink request, int generation) async {
    try {
      final progress = await widget.client.pollLink(request);
      if (!mounted || generation != _generation) return;
      switch (progress) {
        case shared.AtomicLinkProgress.pending:
          _timer = Timer(_every(request), () => _poll(request, generation));
        case shared.AtomicLinkProgress.expired:
          setState(() => _error = 'That code expired. Start again.');
        case shared.AtomicLinkProgress.approved:
          await widget.save(widget.client.exportSession());
          if (mounted) Navigator.pop(context, true);
      }
    } catch (e) {
      if (!mounted || generation != _generation) return;
      // The portal limits how often it is asked: wait and ask again, the
      // code stays good.
      if (_isRateLimit(e)) {
        _timer = Timer(_every(request) * 3, () => _poll(request, generation));
      } else {
        setState(() => _error = _friendly(e));
      }
    }
  }

  Uri _url(shared.AtomicDeviceLink request) => request.wantsIdentity
      ? request.sendIdentityUrl(
          shared.AtomicAccountClient.appOrigin(widget.client.origin))
      : request.approvalUrl;

  /// Not faster than every three seconds: the code does not get approved
  /// sooner for being asked more often.
  Duration _every(shared.AtomicDeviceLink request) =>
      request.interval < const Duration(seconds: 3)
          ? const Duration(seconds: 3)
          : request.interval;

  static bool _isRateLimit(Object e) =>
      '$e'.toLowerCase().contains('too many attempts');

  static String _friendly(Object e) => _isRateLimit(e)
      ? 'Too many attempts. Wait a minute, then try again.'
      : '$e'.replaceFirst('Bad state: ', '');

  @override
  Widget build(BuildContext context) {
    final request = _request;
    final theme = Theme.of(context);
    return AlertDialog(
      title: Text('Connect to ${widget.client.origin.host}'),
      content: SizedBox(
        width: 380,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (request == null && _error == null)
                const LinearProgressIndicator()
              else if (request != null) ...[
                Text(request.wantsIdentity
                    ? 'Open the page in your browser and check that it shows '
                        'this code.'
                    : 'Open ${widget.client.origin.host}/link on a device where '
                        'you are signed in, and enter this code.'),
                const SizedBox(height: 16),
                Center(
                  child: GestureDetector(
                    onTap: () {
                      Clipboard.setData(ClipboardData(text: request.userCode));
                    },
                    child: SelectableText(request.userCode,
                        style: theme.textTheme.headlineMedium
                            ?.copyWith(letterSpacing: 4)),
                  ),
                ),
                const SizedBox(height: 12),
                Row(children: [
                  const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2)),
                  const SizedBox(width: 8),
                  Text('Waiting for approval…',
                      style: theme.textTheme.bodySmall),
                ]),
                if (_error == null && widget.openInBrowser != null) ...[
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    icon: const Icon(Icons.open_in_browser, size: 18),
                    label: const Text('Open in your browser'),
                    onPressed: () => widget.openInBrowser!(_url(request)),
                  ),
                ],
              ],
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
                TextButton(onPressed: _start, child: const Text('Try again')),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel')),
      ],
    );
  }
}
