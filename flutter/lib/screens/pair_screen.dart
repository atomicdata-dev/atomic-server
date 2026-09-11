import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../atomic/atomic_client.dart';
import '../atomic/session.dart';

/// DID prefix for Iroh node identifiers.
const _nodeDidPrefix = 'did:ad:node:';

/// The `atomic:pair` URI the data-browser and the Tauri apps put in their QR
/// codes. See `planning/device-pairing.md` and `browser/lib/src/pairing.ts` —
/// this parser must accept what those produce.
const _pairingUriPrefix = 'atomic:pair?';

/// The form codes had before the double slash was dropped. A QR printed
/// before then must keep scanning.
const _legacyPairingUriPrefix = 'atomic://pair?';

enum _Step { loading, showQr, syncing, done, error }

/// Parsed result from a QR code or DID URI.
///
/// A pairing code is **routing only**: it says which node to reach, and
/// optionally where else to find it. It grants nothing — the node dialed still
/// proves it holds the same agent key before any resource crosses.
class PeerInfo {
  PeerInfo(this.nodeId, [this.name = '', this.serverUrl, this.drives]);

  final String nodeId;
  final String name;

  /// An http(s) server the code advertises — a routing hint, never identity.
  /// Set when the code came from a browser signed in to a reachable server.
  final String? serverUrl;

  /// Which drives to sync. Null means all of the agent's drives.
  final List<String>? drives;
}

class PairScreen extends StatefulWidget {
  /// If non-null, skip straight to syncing with this node ID (from deep link).
  final String? initialNodeId;

  const PairScreen({super.key, this.initialNodeId});

  static Future<int?> show(BuildContext context, {String? nodeId}) {
    return showDialog<int>(
      context: context,
      builder: (_) => PairScreen(initialNodeId: nodeId),
    );
  }

  /// Parse a QR code value into a PeerInfo. Null when it is not a pairing code
  /// this app understands.
  ///
  /// Formats:
  ///  - `atomic://pair?v=1&node=did:ad:node:<hex>&url=<server>&drives=<a>&drives=<b>`
  ///    — what the data-browser and Tauri apps show, including the code a
  ///    browser shows for the server its drives live on.
  ///  - `did:ad:node:<hex>:<name>` / `did:ad:node:<hex>` / raw hex / `iroh:<hex>`
  ///    — this app's own code, and anything pasted by hand.
  static PeerInfo? parsePeerInfo(String input) {
    final trimmed = input.trim();

    if (trimmed.startsWith(_pairingUriPrefix) ||
        trimmed.startsWith(_legacyPairingUriPrefix)) {
      return _parsePairingUri(trimmed);
    }

    var value = trimmed;
    String name = '';

    if (value.startsWith(_nodeDidPrefix)) {
      value = value.substring(_nodeDidPrefix.length);
      // Check for :<name> suffix after the 64-char hex
      if (value.length > 64 && value[64] == ':') {
        name = Uri.decodeComponent(value.substring(65));
        value = value.substring(0, 64);
      }
    }
    if (value.startsWith('iroh:')) value = value.substring(5);
    if (RegExp(r'^[a-f0-9]{64}$').hasMatch(value)) {
      return PeerInfo(value, name);
    }
    return null;
  }

  /// Reads an `atomic:pair?…` envelope (or the older `atomic://pair?…`).
  ///
  /// An unknown version is refused rather than read as far as it parses: a
  /// newer code may mean something this app would get wrong, and dialing the
  /// wrong node on a half-understood code is worse than saying no.
  static PeerInfo? _parsePairingUri(String uri) {
    final prefix = uri.startsWith(_pairingUriPrefix)
        ? _pairingUriPrefix
        : _legacyPairingUriPrefix;
    final params = Uri.splitQueryString(uri.substring(prefix.length));

    final version = params['v'];

    if (version != null && version != '1') return null;

    final node = params['node'];

    if (node == null || !node.startsWith(_nodeDidPrefix)) return null;

    final nodeId = node.substring(_nodeDidPrefix.length);

    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(nodeId)) return null;

    // `drives` repeats for multiple drives, which splitQueryString collapses to
    // the last one — so read them off the raw query instead. `*` means all.
    final drives = Uri.parse(uri)
        .queryParametersAll['drives']
        ?.where((d) => d != '*')
        .toList();

    return PeerInfo(
      nodeId,
      '',
      params['url'],
      drives == null || drives.isEmpty ? null : drives,
    );
  }

  /// Format a QR code value with optional device name.
  static String formatQrValue(String nodeId, String deviceName) {
    if (deviceName.isEmpty) return '$_nodeDidPrefix$nodeId';
    return '$_nodeDidPrefix$nodeId:${Uri.encodeComponent(deviceName)}';
  }

  /// Get the local device name from the OS.
  static Future<String> getDeviceName() async {
    try {
      const channel = MethodChannel('app.atomicdata.canvas/deeplink');
      final name = await channel.invokeMethod<String>('getDeviceName');
      return name ?? Platform.localHostname;
    } catch (_) {
      return Platform.localHostname;
    }
  }

  @override
  State<PairScreen> createState() => _PairScreenState();
}

class _PairScreenState extends State<PairScreen> {
  _Step _step = _Step.loading;
  String? _myNodeId;
  String? _scannedNodeId;
  String? _scannedName;
  String? _error;
  PeerSyncResult? _syncResult;
  bool _scanned = false;
  MobileScannerController? _scanController;
  String _deviceName = '';

  @override
  void initState() {
    super.initState();
    _loadDeviceName();
    _ensurePeerStarted();
  }

  void _loadDeviceName() async {
    // Prefer persisted name, fall back to OS name
    var name = await AtomicClient.getDeviceName();
    if (name.isEmpty) {
      name = await PairScreen.getDeviceName();
      if (name.isNotEmpty && name != 'localhost') {
        await AtomicClient.setDeviceName(name);
      }
    }
    if (mounted) setState(() => _deviceName = name);
  }

  @override
  void dispose() {
    _scanController?.dispose();
    super.dispose();
  }

  Future<void> _ensurePeerStarted() async {
    try {
      var nodeId = await AtomicClient.getPeerId();
      nodeId ??= await AtomicClient.startPeer();
      // Start camera immediately
      _scanController = MobileScannerController();
      setState(() {
        _myNodeId = nodeId;
        _step = _Step.showQr;
      });

      if (widget.initialNodeId != null) {
        _scannedNodeId = widget.initialNodeId;
        _doSync(widget.initialNodeId!);
      }
    } catch (e) {
      setState(() {
        _error = 'Failed to start peer: $e';
        _step = _Step.error;
      });
    }
  }

  void _onDetect(BarcodeCapture capture) {
    if (_scanned) return;
    final barcode = capture.barcodes.firstOrNull;
    if (barcode == null || barcode.rawValue == null) return;

    final peer = PairScreen.parsePeerInfo(barcode.rawValue!);
    if (peer == null) return;

    _scanned = true;
    _scanController?.stop();
    _scannedNodeId = peer.nodeId;
    _scannedName = peer.name;

    // A code from a browser names the server its drives live on. Remember it,
    // so it shows up in settings — but don't switch to it: syncing with the
    // node is what was asked for, and where this device syncs through is a
    // choice that stays the owner's.
    if (peer.serverUrl != null && peer.serverUrl!.isNotEmpty) {
      unawaited(AtomicSession.addKnownServer(peer.serverUrl!));
    }

    _adoptDriveThenSync(peer);
  }

  /// A sync is of a drive, and a device holding only a secret has none — the
  /// key says who you are, never what you have. So the code's `drives` is what
  /// gets it unstuck: it names what to ask the other device for.
  ///
  /// Only when there is nothing here yet. A device that already has a workspace
  /// scanned this code to sync *that*, not to be handed a different one.
  Future<void> _adoptDriveThenSync(PeerInfo peer) async {
    final named = peer.drives?.firstOrNull;

    if (named != null && AtomicClient.getActiveDrive() == null) {
      try {
        await AtomicClient.setActiveDrive(named);
        await AtomicSession.saveDrive(named);
      } catch (e) {
        if (!mounted) return;

        setState(() {
          _error = 'Could not open the workspace that code names: $e';
          _step = _Step.error;
        });

        return;
      }
    }

    await _doSync(peer.nodeId, peer.name);
  }

  Future<void> _doSync(String nodeId, [String name = '']) async {
    if (!mounted) return;
    setState(() {
      _step = _Step.syncing;
      _error = null;
    });
    try {
      final result = await AtomicClient.peerSync(nodeId).timeout(
        const Duration(seconds: 25),
        onTimeout: () => throw Exception(
          'Sync timed out after 25s. Keep both devices open on Wi‑Fi and try again.',
        ),
      );
      await AtomicClient.addKnownPeer(nodeId, name);
      if (!mounted) return;
      setState(() {
        _syncResult = result;
        _step = _Step.done;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _step = _Step.error;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final screenWidth = MediaQuery.of(context).size.width;
    final isPhone = screenWidth < 600;

    return AlertDialog(
      insetPadding: EdgeInsets.symmetric(
        horizontal: isPhone ? 16 : 40,
        vertical: 24,
      ),
      content: SizedBox(
        width: isPhone ? screenWidth * 0.85 : 360.0,
        child: AnimatedSwitcher(
          duration: const Duration(milliseconds: 200),
          child: _buildStep(theme),
        ),
      ),
      actions: _buildActions(theme),
    );
  }

  List<Widget> _buildActions(ThemeData theme) {
    switch (_step) {
      case _Step.loading:
      case _Step.syncing:
        return [];
      case _Step.showQr:
        return [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
        ];
      case _Step.done:
        return [
          FilledButton(
            onPressed: () => Navigator.pop(context, _syncResult?.imported ?? 0),
            child: const Text('Done'),
          ),
        ];
      case _Step.error:
        return [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          const SizedBox(width: 16),
          TextButton(
            onPressed: () {
              if (_scannedNodeId != null) {
                _doSync(_scannedNodeId!, _scannedName ?? '');
              } else {
                setState(() => _step = _Step.showQr);
              }
            },
            child: const Text('Retry'),
          ),
        ];
    }
  }

  Widget _buildStep(ThemeData theme) {
    switch (_step) {
      case _Step.loading:
        return const SizedBox(
          key: ValueKey('loading'),
          height: 200,
          child: Center(child: CircularProgressIndicator()),
        );

      case _Step.showQr:
        final qrData = PairScreen.formatQrValue(_myNodeId!, _deviceName);
        return Column(
          key: const ValueKey('qr'),
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Pair Device', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(
              'Show your QR or scan theirs',
              style: TextStyle(
                  fontSize: 13, color: theme.colorScheme.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            // QR code
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(10),
              ),
              child: QrImageView(
                data: qrData,
                version: QrVersions.auto,
                size: 180,
                backgroundColor: Colors.white,
              ),
            ),
            const SizedBox(height: 6),
            if (_deviceName.isNotEmpty)
              Text(_deviceName,
                  style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                      color: theme.colorScheme.onSurface)),
            const SizedBox(height: 8),
            // Camera scanner (compact)
            if (_scanController != null)
              SizedBox(
                height: 100,
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(8),
                  child: MobileScanner(
                    controller: _scanController!,
                    onDetect: _onDetect,
                  ),
                ),
              ),
          ],
        );

      case _Step.syncing:
        final label = (_scannedName != null && _scannedName!.isNotEmpty)
            ? _scannedName!
            : '${_scannedNodeId!.substring(0, 12)}...';
        return SizedBox(
          key: const ValueKey('syncing'),
          height: 200,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const CircularProgressIndicator(),
              const SizedBox(height: 16),
              Text(
                'Connecting to $label',
                style: TextStyle(
                    fontSize: 13, color: theme.colorScheme.onSurfaceVariant),
              ),
            ],
          ),
        );

      case _Step.done:
        final label = (_scannedName != null && _scannedName!.isNotEmpty)
            ? _scannedName!
            : 'device';
        return Column(
          key: const ValueKey('done'),
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.check_circle, color: Colors.green, size: 48),
            const SizedBox(height: 12),
            Text('Paired with $label', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            // What happened, both directions. "Synced 0 resources" was true of
            // a workspace sent somewhere that had none, and of two devices
            // already holding the same thing — and read as failure for both.
            Text(
              _syncResult?.describe() ?? 'Nothing to sync',
              style: TextStyle(
                  fontSize: 13, color: theme.colorScheme.onSurfaceVariant),
            ),
          ],
        );

      case _Step.error:
        return Column(
          key: const ValueKey('error'),
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, color: Colors.red, size: 48),
            const SizedBox(height: 12),
            Text('Connection Failed', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            SelectableText(
              _error ?? 'Unknown error',
              style: const TextStyle(fontSize: 12, color: Colors.red),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            TextButton.icon(
              icon: const Icon(Icons.copy, size: 16),
              label: const Text('Copy error'),
              onPressed: () {
                Clipboard.setData(
                    ClipboardData(text: _error ?? 'Unknown error'));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Error copied'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
          ],
        );
    }
  }
}
