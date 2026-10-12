import 'dart:async';
import 'package:flutter/material.dart';
import 'client.dart';

/// Shared browser approval UI. The host owns launching and credential storage.
/// Closing cancels polling; late replies never install a recovered identity.
class AtomicAccountLinkDialog extends StatefulWidget {
  const AtomicAccountLinkDialog(
      {super.key,
      required this.client,
      required this.deviceName,
      required this.openUrl,
      required this.install});
  final AtomicAccountClient client;
  final String deviceName;
  final Future<void> Function(Uri) openUrl;
  final Future<void> Function(AtomicRecoveredIdentity, String session) install;
  static Future<bool> show(
    BuildContext context, {
    required AtomicAccountClient client,
    required String deviceName,
    required Future<void> Function(Uri) openUrl,
    required Future<void> Function(AtomicRecoveredIdentity, String) install,
  }) async =>
      await showDialog<bool>(
          context: context,
          builder: (_) => AtomicAccountLinkDialog(
              client: client,
              deviceName: deviceName,
              openUrl: openUrl,
              install: install)) ??
      false;
  @override
  State<AtomicAccountLinkDialog> createState() => _LinkState();
}

class _LinkState extends State<AtomicAccountLinkDialog> {
  AtomicDeviceLink? _request;
  AtomicRecoveredIdentity? _identity;
  String? _error;
  Timer? _timer;
  bool _busy = false;
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
      _error = null;
      _request = null;
      _identity = null;
      _busy = true;
    });
    try {
      final request = await widget.client.requestLink(widget.deviceName);
      if (!mounted || generation != _generation) return;
      setState(() {
        _request = request;
        _busy = false;
      });
      _timer = Timer(request.interval, () => _poll(generation));
    } catch (e) {
      if (mounted && generation == _generation) {
        setState(() {
          _error = '$e';
          _busy = false;
        });
      }
    }
  }

  Future<void> _poll(int generation) async {
    try {
      final result = await widget.client.pollLink(_request!);
      if (!mounted || generation != _generation) return;
      switch (result) {
        case AtomicLinkProgress.pending:
          _timer = Timer(_request!.interval, () => _poll(generation));
        case AtomicLinkProgress.expired:
          setState(() =>
              _error = 'This code expired. Start again to get a new one.');
        case AtomicLinkProgress.approved:
          setState(() => _busy = true);
          final identity = await widget.client.recoverIdentity();
          if (!mounted || generation != _generation) return;
          setState(() {
            _identity = identity;
            _busy = false;
          });
      }
    } catch (e) {
      if (mounted && generation == _generation) {
        setState(() {
          _error = '$e';
          _busy = false;
        });
      }
    }
  }

  Future<void> _install() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.install(_identity!, widget.client.exportSession());
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
          _busy = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) => PopScope(
      canPop: !_busy || _identity == null,
      child: AlertDialog(
        title: const Text('Connect your account'),
        content: SizedBox(
            width: 380,
            child: SingleChildScrollView(
                child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(widget.client.origin.host),
                const SizedBox(height: 16),
                if (_busy) const LinearProgressIndicator(),
                if (_identity case final identity?) ...[
                  Text(identity.address,
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 12),
                  const Text(
                      'Open this account in the app. Your local projects will be kept separately.'),
                ] else if (_request case final request?) ...[
                  const Text(
                      'Sign in or create your account in the browser, then approve this device.'),
                  const SizedBox(height: 16),
                  SelectableText(request.userCode,
                      style: Theme.of(context).textTheme.headlineMedium),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                      onPressed: () async {
                        try {
                          await widget.openUrl(request.approvalUrl);
                        } catch (_) {
                          if (mounted) {
                            setState(
                                () => _error = 'Could not open the browser');
                          }
                        }
                      },
                      icon: const Icon(Icons.open_in_browser),
                      label: const Text('Open browser')),
                  const SizedBox(height: 8),
                  const Text('Waiting for browser approval…'),
                ],
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  Text(_error!,
                      style: TextStyle(
                          color: Theme.of(context).colorScheme.error)),
                  TextButton(onPressed: _start, child: const Text('Try again')),
                ],
              ],
            ))),
        actions: [
          TextButton(
              onPressed: _busy && _identity != null
                  ? null
                  : () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          if (_identity != null)
            FilledButton(
                onPressed: _busy ? null : _install,
                child: const Text('Use this account')),
        ],
      ));
}
