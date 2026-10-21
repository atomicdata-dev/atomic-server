import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart' show timeAgo;
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';

/// The Sync screen's "This device" section: who this device is, what it runs,
/// how much of your data it stores (per workspace), and how it syncs. Every
/// line is read from the host; what it cannot tell is left out.
///
/// The count of stored data is slow on a big store, so it is asked once the
/// card is shown and a spinner stands in until it answers. A count that fails
/// shows nothing at all, not an error.
class ThisDeviceCard extends StatefulWidget {
  const ThisDeviceCard({
    super.key,
    required this.backend,
    required this.deviceName,
    required this.peerId,
    required this.identity,
    required this.driveNames,
    required this.onRename,
  });

  final shared.AtomicSettingsBackend backend;
  final String deviceName;

  /// This device's node id, null while it is not online.
  final String? peerId;

  /// The agent's subject (its public key), shown shortened.
  final String? identity;

  /// Workspace names the screen already read, for a drive the count has no
  /// name for.
  final Map<String, String> driveNames;
  final VoidCallback onRename;

  @override
  State<ThisDeviceCard> createState() => _ThisDeviceCardState();
}

class _ThisDeviceCardState extends State<ThisDeviceCard> {
  shared.StoreStats? _stats;
  bool _counting = true;
  List<Map<String, String>> _peers = const [];
  Set<String> _live = const {};

  @override
  void initState() {
    super.initState();
    unawaited(_count());
    unawaited(_loadPeers());
  }

  Future<void> _count({bool refresh = false}) async {
    setState(() => _counting = true);
    shared.StoreStats? stats;
    try {
      stats = await widget.backend.storeStats(refresh: refresh);
    } catch (_) {
      stats = null;
    }
    if (!mounted) return;
    setState(() {
      _stats = stats ?? (refresh ? null : _stats);
      _counting = false;
    });
  }

  Future<void> _loadPeers() async {
    try {
      final peers = await widget.backend.getKnownPeers();
      final live = await widget.backend.livePeerIds();
      if (mounted) {
        setState(() {
          _peers = peers;
          _live = live;
        });
      }
    } catch (_) {
      // No peers to count: the lines about them are left out.
    }
  }

  int? get _lastSyncedMs {
    int? newest;
    for (final p in _peers) {
      final t = int.tryParse(p['last_synced'] ?? '');
      if (t != null && (newest == null || t > newest)) newest = t;
    }
    return newest;
  }

  int get _syncedWith =>
      _peers.where((p) => int.tryParse(p['last_synced'] ?? '') != null).length;

  @override
  Widget build(BuildContext context) {
    final c = shared.syncColors(context);
    final info = widget.backend.deviceInfo();
    final online = widget.peerId != null;
    final name = widget.deviceName.isEmpty ? 'This device' : widget.deviceName;
    final last = _lastSyncedMs;
    final stats = _stats;

    return shared.SyncSection(
      title: 'This device',
      children: [
        InkWell(
          key: const Key('this-device-name'),
          onTap: widget.onRename,
          child: ConstrainedBox(
            constraints: const BoxConstraints(minHeight: 64),
            child: Padding(
              padding: const EdgeInsets.symmetric(
                  horizontal: shared.SyncGap.l, vertical: shared.SyncGap.m),
              child: Row(children: [
                Icon(Icons.phone_android, size: 24, color: c.main),
                const SizedBox(width: shared.SyncGap.m),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(name, style: shared.SyncText.bodyStrong(c)),
                      if (info != null && info.platformLine.isNotEmpty)
                        Text(info.platformLine,
                            style: shared.SyncText.caption(c)),
                    ],
                  ),
                ),
                shared.StatusChip(online ? 'Online' : 'Offline',
                    tone: online
                        ? shared.SyncTone.success
                        : shared.SyncTone.neutral),
                const SizedBox(width: shared.SyncGap.s),
                Icon(Icons.edit_outlined, size: 20, color: c.textSecondary),
              ]),
            ),
          ),
        ),
        if (info?.appVersion != null)
          shared.KeyValueRow(
              label: 'Version',
              value: info!.appVersion!,
              icon: Icons.info_outline),
        if (widget.peerId != null)
          shared.KeyValueRow(
            key: const Key('copy-device-id'),
            label: 'Device ID',
            value: shared.shortId(widget.peerId!),
            copy: widget.peerId,
            copyLabel: 'Device ID',
            icon: Icons.fingerprint,
            mono: true,
          ),
        if (widget.identity != null)
          shared.KeyValueRow(
            key: const Key('copy-identity'),
            label: 'Identity',
            value: shared.shortId(widget.identity!),
            copy: widget.identity,
            copyLabel: 'Identity',
            icon: Icons.badge_outlined,
            mono: true,
          ),
        ..._storage(c, stats),
        if (_peers.isNotEmpty)
          shared.KeyValueRow(
            label: 'Synced with',
            value: _syncedWith == 0
                ? 'No device yet'
                : '$_syncedWith ${_syncedWith == 1 ? 'device' : 'devices'}',
            icon: Icons.sync,
          ),
        if (last != null)
          shared.KeyValueRow(
              label: 'Last sync', value: timeAgo(last), icon: Icons.schedule),
        if (_peers.isNotEmpty)
          shared.KeyValueRow(
            label: 'Connected now',
            value: _peers.where((p) => _live.contains(p['node_id'])).isEmpty
                ? 'None'
                : '${_peers.where((p) => _live.contains(p['node_id'])).length}',
            icon: Icons.wifi_tethering,
          ),
      ],
    );
  }

  List<Widget> _storage(shared.AppColors c, shared.StoreStats? stats) {
    if (stats == null) {
      // Counting: a spinner. Failed or unsupported: nothing.
      return [
        if (_counting)
          const shared.KeyValueRow(
            key: Key('stats-loading'),
            label: 'Data on this device',
            valueWidget: Align(
                alignment: Alignment.centerRight, child: shared.SyncSpinner()),
            icon: Icons.storage_outlined,
          ),
      ];
    }
    final total = stats.barTotal;
    return [
      shared.KeyValueRow(
        key: const Key('stats-total'),
        label: 'Data on this device',
        value:
            '${shared.formatBytes(stats.dataBytes)} · ${shared.formatResources(stats.resources)}',
        icon: Icons.storage_outlined,
        trailing: _counting
            ? const shared.SyncSpinner()
            : IconButton(
                tooltip: 'Count again',
                icon: const Icon(Icons.refresh, size: 20),
                color: c.textSecondary,
                constraints: const BoxConstraints(minWidth: 48, minHeight: 48),
                onPressed: () => _count(refresh: true),
              ),
      ),
      if (stats.diskBytes != null)
        shared.KeyValueRow(
          key: const Key('stats-disk'),
          label: 'Store on disk',
          value: shared.formatBytes(stats.diskBytes!),
          icon: Icons.sd_storage_outlined,
        ),
      if (stats.fileBytes > 0)
        shared.KeyValueRow(
          label: 'Files',
          value: shared.formatBytes(stats.fileBytes),
          icon: Icons.attach_file,
        ),
      for (final d in stats.drives)
        _driveRow(c, d, total == 0 ? 0 : d.bytes / total),
    ];
  }

  Widget _driveRow(shared.AppColors c, shared.DriveStats d, double share) {
    final name = d.name.isNotEmpty
        ? d.name
        : (widget.driveNames[d.subject]?.isNotEmpty ?? false)
            ? widget.driveNames[d.subject]!
            : 'Workspace';
    return Padding(
      key: ValueKey('drive-row-${d.subject}'),
      padding: const EdgeInsets.symmetric(
          horizontal: shared.SyncGap.l, vertical: shared.SyncGap.m),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Expanded(
                child: Text(name,
                    style: shared.SyncText.body(c),
                    overflow: TextOverflow.ellipsis)),
            const SizedBox(width: shared.SyncGap.m),
            Text(
                '${shared.formatBytes(d.bytes)} · ${shared.formatResources(d.resources)}',
                style: shared.SyncText.caption(c)),
          ]),
          const SizedBox(height: shared.SyncGap.s),
          shared.ShareBar(share),
        ],
      ),
    );
  }
}
