import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart' show timeAgo;
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

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
    this.onOpenStorage,
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

  /// Opens the web app's storage page for a drive ([subject], its [name]).
  /// Without it the drive rows are not tappable.
  final void Function(String subject, String name)? onOpenStorage;

  /// Where the Storage row's expanded state is kept.
  static const expandedKey = 'sync_storage_expanded';

  @override
  State<ThisDeviceCard> createState() => _ThisDeviceCardState();
}

class _ThisDeviceCardState extends State<ThisDeviceCard> {
  shared.StoreStats? _stats;
  bool _counting = true;
  List<Map<String, String>> _peers = const [];
  Set<String> _live = const {};
  bool _expanded = false;

  @override
  void initState() {
    super.initState();
    unawaited(_loadExpanded());
    unawaited(_count());
    unawaited(_loadPeers());
  }

  Future<void> _loadExpanded() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final v = prefs.getBool(ThisDeviceCard.expandedKey) ?? false;
      if (mounted && v != _expanded) setState(() => _expanded = v);
    } catch (_) {
      // No stored choice: collapsed.
    }
  }

  Future<void> _toggle() async {
    setState(() => _expanded = !_expanded);
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool(ThisDeviceCard.expandedKey, _expanded);
    } catch (_) {
      // Kept for this session only.
    }
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
              padding: const EdgeInsets.only(
                  left: shared.SyncGap.l,
                  right: shared.KeyValueGrid.rightInset,
                  top: shared.SyncGap.s,
                  bottom: shared.SyncGap.s),
              child: Row(children: [
                Icon(Icons.phone_android, size: 24, color: c.main),
                const SizedBox(width: shared.SyncGap.m),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(name,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: shared.SyncText.bodyStrong(c)),
                      if (info != null && info.platformLine.isNotEmpty)
                        Text(info.platformLine,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: shared.SyncText.caption(c)),
                    ],
                  ),
                ),
                SizedBox(
                  width: shared.KeyValueGrid.trailingSlot,
                  child: Center(
                      child: Icon(Icons.edit_outlined,
                          size: 20, color: c.textSecondary)),
                ),
              ]),
            ),
          ),
        ),
        shared.KeyValueRow(
          key: const Key('this-device-status'),
          label: 'Status',
          icon: Icons.circle_outlined,
          valueWidget: shared.StatusChip(online ? 'Online' : 'Offline',
              tone: online ? shared.SyncTone.success : shared.SyncTone.neutral),
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
            label: 'Storage',
            valueWidget: shared.SyncSpinner(),
            icon: Icons.storage_outlined,
          ),
      ];
    }
    final total = stats.barTotal;
    final n = stats.drives.length;
    final caption = [
      shared.formatResources(stats.resources),
      if (stats.fileBytes > 0) '${shared.formatBytes(stats.fileBytes)} files',
    ].join(' · ');
    return [
      Column(
        key: const Key('stats-group'),
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          shared.KeyValueRow(
            key: const Key('stats-total'),
            label: 'Storage',
            value:
                '${shared.formatBytes(stats.dataBytes)} · $n ${n == 1 ? 'drive' : 'drives'}',
            subtitle: caption,
            icon: Icons.storage_outlined,
            expanded: _expanded,
            onTap: _toggle,
            trailing: Icon(_expanded ? Icons.expand_less : Icons.expand_more,
                size: 24, color: c.textSecondary),
          ),
          AnimatedSize(
            duration: const Duration(milliseconds: 200),
            curve: Curves.easeInOut,
            alignment: Alignment.topCenter,
            child: _expanded
                ? Column(
                    key: const Key('stats-drives'),
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      for (final d in stats.drives)
                        _driveRow(c, d, total == 0 ? 0 : d.bytes / total),
                      Padding(
                        padding: const EdgeInsets.only(
                            left: shared.SyncGap.m, bottom: shared.SyncGap.xs),
                        child: _counting
                            ? const SizedBox(
                                height: 48,
                                child: Padding(
                                    padding: EdgeInsets.only(
                                        left: 40 + shared.SyncGap.m),
                                    child: Align(
                                        alignment: Alignment.centerLeft,
                                        child: shared.SyncSpinner())))
                            : Padding(
                                padding: const EdgeInsets.only(left: 40),
                                child: shared.SyncTextAction(
                                    key: const Key('stats-recount'),
                                    label: 'Count again',
                                    icon: Icons.refresh,
                                    onPressed: () => _count(refresh: true)),
                              ),
                      ),
                    ],
                  )
                : const SizedBox(width: double.infinity),
          ),
        ],
      ),
      if (stats.diskBytes != null)
        shared.KeyValueRow(
          key: const Key('stats-disk'),
          label: 'On disk',
          value: shared.formatBytes(stats.diskBytes!),
          icon: Icons.sd_storage_outlined,
        ),
    ];
  }

  /// One drive: name and size on the label/value grid's left edge, the share
  /// bar below, a chevron in the trailing slot when the page can open.
  Widget _driveRow(shared.AppColors c, shared.DriveStats d, double share) {
    final name = d.name.isNotEmpty
        ? d.name
        : (widget.driveNames[d.subject]?.isNotEmpty ?? false)
            ? widget.driveNames[d.subject]!
            : 'Workspace';
    final open = widget.onOpenStorage;
    final row = ConstrainedBox(
      constraints:
          const BoxConstraints(minHeight: shared.KeyValueGrid.rowHeight),
      child: Padding(
        // Text starts at the label column (16 + 24 icon + 12 gap).
        padding: const EdgeInsets.only(
            left: shared.SyncGap.l + 24 + shared.SyncGap.m,
            right: shared.KeyValueGrid.rightInset,
            top: shared.SyncGap.s,
            bottom: shared.SyncGap.s),
        child: Row(children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(children: [
                  Expanded(
                      child: Text(name,
                          maxLines: 1,
                          style: shared.SyncText.body(c),
                          overflow: TextOverflow.ellipsis)),
                  const SizedBox(width: shared.SyncGap.m),
                  Text(shared.formatBytes(d.bytes),
                      maxLines: 1, style: shared.SyncText.caption(c)),
                ]),
                Text(shared.formatResources(d.resources),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: shared.SyncText.caption(c)),
                const SizedBox(height: shared.SyncGap.s),
                shared.ShareBar(share),
              ],
            ),
          ),
          SizedBox(
            width: shared.KeyValueGrid.trailingSlot,
            child: Center(
                child: open == null
                    ? null
                    : Icon(Icons.chevron_right,
                        size: 24, color: c.textSecondary)),
          ),
        ]),
      ),
    );
    return KeyedSubtree(
      key: ValueKey('drive-row-${d.subject}'),
      child: open == null
          ? row
          : InkWell(
              onTap: () => open(d.subject, name),
              child: Semantics(
                  button: true, label: 'Storage of $name', child: row)),
    );
  }
}
