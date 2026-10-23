import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:atomic_chat/atomic_chat.dart' show AppTopBar;
import 'package:atomic_flutter/atomic_flutter.dart'
    show
        SyncActionButton,
        SyncButtonKind,
        SyncGap,
        SyncText,
        SyncTone,
        SyncToneColors,
        syncColors;
import 'package:flutter/services.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart' show PairingCode;
import 'package:qr_flutter/qr_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../atomic/atomic_client.dart';
import '../atomic/session.dart';
import 'scanner_frame.dart';

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
    // A page, not a dialog: nothing of the screen it was opened from stays
    // visible behind the result.
    return Navigator.of(context).push<int>(MaterialPageRoute<int>(
      fullscreenDialog: true,
      builder: (_) => PairScreen(initialNodeId: nodeId),
    ));
  }

  /// Parse a QR code value into a PeerInfo. Null when it is not a pairing code
  /// this app understands. The formats are `PairingCode.parse`'s (the package
  /// owns them): `atomic://pair?…` from the web and desktop apps,
  /// `atomic:node:<id>`, `did:ad:node:<id>[:<name>]`, raw hex and `iroh:<id>`.
  static PeerInfo? parsePeerInfo(String input) {
    final code = PairingCode.parse(input);
    return code == null
        ? null
        : PeerInfo(code.nodeId, code.name, code.serverUrl, code.drives);
  }

  /// Format a QR code value with optional device name.
  static String formatQrValue(String nodeId, String deviceName) =>
      PairingCode.format(nodeId, deviceName);

  /// Get the local device name from the OS.
  static Future<String> getDeviceName() async {
    try {
      const channel = MethodChannel('app.atomicdata.app/deeplink');
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
    final actions = _buildActions(theme);
    return Scaffold(
      appBar: const AppTopBar(title: 'Pair a device'),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 520),
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 200),
                child: _buildStep(theme),
              ),
            ),
          ),
        ),
      ),
      bottomNavigationBar: actions.isEmpty
          ? null
          : SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(24, 8, 24, 16),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: actions,
                ),
              ),
            ),
    );
  }

  List<Widget> _buildActions(ThemeData theme) {
    switch (_step) {
      case _Step.loading:
      case _Step.syncing:
        return [];
      case _Step.showQr:
        return [
          SyncActionButton(
            label: 'Cancel',
            onPressed: () => Navigator.pop(context),
          ),
        ];
      case _Step.done:
        return [
          SyncActionButton(
            label: 'Done',
            kind: SyncButtonKind.primary,
            onPressed: () => Navigator.pop(context, _syncResult?.imported ?? 0),
          ),
        ];
      case _Step.error:
        return [
          SyncActionButton(
            label: 'Cancel',
            onPressed: () => Navigator.pop(context),
          ),
          const SizedBox(width: SyncGap.m),
          SyncActionButton(
            label: 'Retry',
            kind: SyncButtonKind.primary,
            onPressed: () {
              if (_scannedNodeId != null) {
                _doSync(_scannedNodeId!, _scannedName ?? '');
              } else {
                setState(() => _step = _Step.showQr);
              }
            },
          ),
        ];
    }
  }

  Widget _buildStep(ThemeData theme) {
    final c = syncColors(context);
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
            Text('Pair Device', style: SyncText.header(c)),
            const SizedBox(height: 8),
            Text(
              'Show your QR or scan theirs',
              style: SyncText.caption(c),
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
              Text(_deviceName, style: SyncText.bodyStrong(c)),
            const SizedBox(height: 8),
            // Camera scanner, at the camera's own shape.
            if (_scanController != null) ...[
              const SizedBox(height: SyncGap.m),
              ValueListenableBuilder<MobileScannerState>(
                valueListenable: _scanController!,
                builder: (context, state, _) => ScannerFrame(
                  cameraSize: state.size,
                  onTorch: () =>
                      _scanController?.toggleTorch().catchError((_) {}),
                  onFlip: () =>
                      _scanController?.switchCamera().catchError((_) {}),
                  child: MobileScanner(
                    controller: _scanController!,
                    onDetect: _onDetect,
                  ),
                ),
              ),
            ],
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
                style: SyncText.caption(c),
              ),
            ],
          ),
        );

      case _Step.done:
        // The name the code carried, else the one the device introduced
        // itself by when it answered.
        final helloName = _syncResult?.peerName ?? '';
        final label = (_scannedName != null && _scannedName!.isNotEmpty)
            ? _scannedName!
            : helloName.isNotEmpty
                ? helloName
                : 'device';
        return Column(
          key: const ValueKey('done'),
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.check_circle,
                color: SyncTone.success.color(c), size: 48),
            const SizedBox(height: 12),
            Text('Paired with $label', style: SyncText.header(c)),
            const SizedBox(height: 8),
            // What happened, both directions. "Synced 0 resources" was true of
            // a workspace sent somewhere that had none, and of two devices
            // already holding the same thing — and read as failure for both.
            Text(
              _syncResult?.counts() ?? 'Nothing to sync',
              key: const ValueKey('pair-result-counts'),
              style: SyncText.caption(c),
            ),
          ],
        );

      case _Step.error:
        return Column(
          key: const ValueKey('error'),
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, color: SyncTone.error.color(c), size: 48),
            const SizedBox(height: 12),
            Text('Connection Failed', style: SyncText.header(c)),
            const SizedBox(height: 8),
            SelectableText(
              _error ?? 'Unknown error',
              style:
                  SyncText.caption(c).copyWith(color: SyncTone.error.color(c)),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            SyncActionButton(
              icon: Icons.copy,
              label: 'Copy error',
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
