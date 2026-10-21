/// One paired device in detail: whose it is, its id, the last sync, and what
/// to do with it. Pops `true` when the person chose to forget it.
library;

import 'package:flutter/material.dart';

import 'paired_device.dart';
import 'sync_widgets.dart';

class PeerDetailsSheet extends StatefulWidget {
  const PeerDetailsSheet({
    super.key,
    required this.device,
    required this.live,
    this.syncPeer,
  });

  final PairedDevice device;
  final bool live;

  /// See [AtomicSettingsBackend.syncPeer]. Null: no "Sync now".
  final Future<String> Function(String nodeId)? syncPeer;

  @override
  State<PeerDetailsSheet> createState() => _PeerDetailsSheetState();
}

class _PeerDetailsSheetState extends State<PeerDetailsSheet> {
  bool _syncing = false;
  String? _result;
  bool _failed = false;

  Future<void> _syncNow() async {
    final sync = widget.syncPeer;
    if (sync == null || _syncing) return;
    setState(() {
      _syncing = true;
      _result = null;
      _failed = false;
    });
    try {
      final result = await sync(widget.device.nodeId);
      if (mounted) setState(() => _result = result);
    } catch (e) {
      if (mounted) {
        setState(() {
          _result = '$e';
          _failed = true;
        });
      }
    } finally {
      if (mounted) setState(() => _syncing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final device = widget.device;
    final lastSynced = device.lastSynced;
    final counts = device.lastSyncCounts;
    final owner = device.agentName ?? device.agent;

    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(SyncGap.l, 0, SyncGap.l, SyncGap.l),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(device.label, style: SyncText.title(c)),
            const SizedBox(height: SyncGap.s),
            Wrap(spacing: SyncGap.s, runSpacing: SyncGap.s, children: [
              StatusChip(widget.live ? 'Connected' : 'Offline',
                  tone: widget.live ? SyncTone.success : SyncTone.neutral),
              if (device.relationLabel != null)
                StatusChip(device.relationLabel!),
            ]),
            const SizedBox(height: SyncGap.m),
            if (device.isOtherPerson)
              Padding(
                padding: const EdgeInsets.only(bottom: SyncGap.s),
                child: Text(
                  'Someone else\'s device. It gets only what they may read: '
                  'the workspaces shared with them.',
                  style: SyncText.caption(c),
                ),
              ),
            if (owner != null)
              KeyValueRow(
                label: 'Signed in as',
                value: owner,
                copy: device.agent,
                copyLabel: 'Agent',
              ),
            KeyValueRow(
              label: 'Device ID',
              value:
                  '${device.nodeId.substring(0, device.nodeId.length.clamp(0, 16))}…',
              copy: device.nodeId,
              copyLabel: 'ID',
              mono: true,
            ),
            KeyValueRow(
              label: 'Last synced',
              value: lastSynced == null ? 'Not yet' : _when(lastSynced),
              subtitle: counts,
            ),
            if (device.drives > 0)
              KeyValueRow(
                label: 'Workspaces',
                value: '${device.drives}',
              ),
            if (_result != null)
              Padding(
                padding: const EdgeInsets.only(top: SyncGap.s),
                child: SyncNote(
                  _result!,
                  tone: _failed ? SyncTone.error : SyncTone.success,
                  icon: _failed ? Icons.error_outline : Icons.check_circle,
                ),
              ),
            const SizedBox(height: SyncGap.m),
            Wrap(spacing: SyncGap.s, runSpacing: SyncGap.s, children: [
              if (widget.syncPeer != null)
                SyncActionButton(
                  label: _syncing ? 'Syncing…' : 'Sync now',
                  icon: Icons.sync,
                  kind: SyncButtonKind.primary,
                  onPressed: _syncing ? null : _syncNow,
                ),
              SyncActionButton(
                label: 'Forget this device',
                icon: Icons.link_off,
                kind: SyncButtonKind.destructive,
                onPressed: () => Navigator.of(context).pop(true),
              ),
            ]),
          ],
        ),
      ),
    );
  }

  static String _when(int millis) {
    final delta =
        DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(millis));
    if (delta.inSeconds < 60) return 'Just now';
    if (delta.inMinutes < 60) return '${delta.inMinutes}m ago';
    if (delta.inHours < 24) return '${delta.inHours}h ago';
    return '${delta.inDays}d ago';
  }
}
