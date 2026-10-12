/// Server settings: which server this device syncs through, and what it costs.
///
/// A sync hub is optional here — the data lives locally and syncs peer-to-peer
/// just as well — so "no server" is a first-class state, not an error.
///
/// Mirrors the data-browser's Sync page: one stable list, the active server
/// marked rather than moved (a list that reorders under the finger that tapped
/// it is a bad list), URLs that do not demand a scheme, and the node's own
/// account of itself read from `/server`.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'settings_backend.dart';
import 'server_info.dart';
import 'server_url.dart';

class ServerSettingsSection extends StatefulWidget {
  const ServerSettingsSection(
      {super.key, required this.backend, this.onServerChanged});

  final AtomicSettingsBackend backend;

  /// Called after the active server changes, so the host can reload whatever
  /// it read from the old one.
  final VoidCallback? onServerChanged;

  @override
  State<ServerSettingsSection> createState() => _ServerSettingsSectionState();
}

class _ServerSettingsSectionState extends State<ServerSettingsSection> {
  List<String> _servers = [];
  String? _active;
  ServerInfo _info = ServerInfo.unknown;
  DriveUsage? _usage;
  // Paired devices (Iroh peers) share this one Devices list with servers — a
  // server is just an always-on device, and the browser lists them together.
  List<Map<String, String>> _peers = [];
  Set<String> _livePeerIds = {};
  bool _loading = true;
  bool _busy = false;
  bool _showAdd = false;
  String? _error;
  final _addController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _addController.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final servers =
          await widget.backend.servers?.knownServers() ?? <String>[];
      final active = await widget.backend.servers?.activeServer();

      // Peers come from the Rust side; tolerate its absence (widget tests, a
      // not-yet-initialized bridge) by showing the servers alone rather than
      // failing the whole list.
      List<Map<String, String>> peers = [];
      Set<String> livePeerIds = {};
      try {
        peers = await widget.backend.getKnownPeers();
        livePeerIds = await widget.backend.livePeerIds();
      } catch (_) {
        // no peers available
      }

      if (!mounted) return;

      setState(() {
        _servers = servers;
        _active = active;
        _peers = peers;
        _livePeerIds = livePeerIds;
        _loading = false;
      });

      await _loadActiveDetails();
    } catch (e) {
      if (mounted) {
        setState(() {
          _loading = false;
          _error = '$e';
        });
      }
    }
  }

  /// The active node's own account of itself, plus what this drive costs there.
  /// Both are best-effort: an unreachable server is a normal state to be in.
  Future<void> _loadActiveDetails() async {
    final active = _active;

    if (active == null) {
      if (mounted) setState(() => _info = ServerInfo.unknown);

      return;
    }

    final info = await widget.backend.servers!.serverInfo(active);

    if (!mounted) return;

    setState(() => _info = info);

    final usage = await widget.backend.servers!.driveUsage(active);

    if (mounted) setState(() => _usage = usage);
  }

  Future<void> _switchTo(String url) async {
    setState(() {
      _busy = true;
      _error = null;
      _usage = null;
      _info = ServerInfo.unknown;
    });

    try {
      await widget.backend.servers!.switchTo(url);

      if (!mounted) return;

      setState(() => _active = normalizeServerUrl(url));
      widget.onServerChanged?.call();
      await _loadActiveDetails();
    } catch (e) {
      // The server stays selected: it is the one the session now points at, and
      // saying so beats silently snapping back to the old one.
      if (mounted) setState(() => _error = 'Could not connect: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _add() async {
    final url = normalizeServerUrl(_addController.text);

    if (url.isEmpty) return;

    await widget.backend.servers!.add(url);
    _addController.clear();

    if (!mounted) return;

    setState(() => _showAdd = false);

    // First server added is the one to use — nothing to choose between.
    if (_active == null) {
      await _switchTo(url);
      await _load();

      return;
    }

    await _load();
  }

  /// Offer this device's workspace to the active server.
  ///
  /// Connecting alone does not do this: a drive made here before any server was
  /// connected has never been pushed, so it exists nowhere else — and a browser
  /// signed in as the same account still sees nothing, because a browser reads
  /// from a server rather than syncing with devices.
  Future<void> _pushWorkspace() async {
    final active = _active;

    if (active == null || _busy) return;

    setState(() {
      _busy = true;
      _error = null;
    });

    try {
      final pushed = await widget.backend.servers!.pushWorkspace(active);

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            pushed == 0
                ? 'Already up to date'
                : 'Synced $pushed ${pushed == 1 ? 'resource' : 'resources'} to ${serverLabel(active)}',
          ),
        ),
      );

      await _loadActiveDetails();
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _runAction(Future<void> Function() action) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _remove(String url) async {
    final wasActive = sameOrigin(url, _active);

    await widget.backend.servers!.remove(url);

    if (wasActive) widget.onServerChanged?.call();

    await _load();
  }

  void _copy(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
          content: Text('$label copied'), duration: const Duration(seconds: 2)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    if (_loading) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 16),
        child: Center(child: CircularProgressIndicator()),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: Text(
            'Devices',
            style: TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ),
        if (_servers.isEmpty && _peers.isEmpty)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Text(
              widget.backend.servers == null
                  ? 'No other devices yet. Pair one below.'
                  : 'No other devices yet. Pair one below, or add an always-on device by address.',
              style: TextStyle(
                fontSize: 12,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        for (final server in _servers) _serverCard(theme, server),
        for (final peer in _peers) _peerCard(theme, peer),
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(
              _error!,
              style: const TextStyle(fontSize: 12, color: Colors.red),
            ),
          ),
        if (_showAdd) _addField(theme) else _addButton(),
      ],
    );
  }

  Widget _serverCard(ThemeData theme, String server) {
    final isActive = sameOrigin(server, _active);
    final scheme = theme.colorScheme;

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(8),
        color: isActive ? scheme.primaryContainer.withValues(alpha: 0.3) : null,
        border: Border.all(
          color: isActive ? scheme.primary : scheme.outlineVariant,
          width: isActive ? 1.5 : 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                isActive ? Icons.cloud_done : Icons.cloud_outlined,
                size: 18,
                color: isActive ? scheme.primary : scheme.onSurfaceVariant,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  serverLabel(server),
                  style: TextStyle(
                    fontSize: 14,
                    fontWeight: isActive ? FontWeight.w600 : FontWeight.normal,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (isActive)
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  decoration: BoxDecoration(
                    color: scheme.primary,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Text(
                    'In use',
                    style: TextStyle(fontSize: 10, color: scheme.onPrimary),
                  ),
                ),
            ],
          ),
          if (isActive) ..._activeDetails(theme),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              if (isActive)
                TextButton(
                  onPressed: _busy ? null : _pushWorkspace,
                  child: const Text(
                    'Sync workspace here',
                    style: TextStyle(fontSize: 12),
                  ),
                ),
              if (!isActive)
                TextButton(
                  onPressed: _busy ? null : () => _switchTo(server),
                  child: const Text('Switch to this',
                      style: TextStyle(fontSize: 12)),
                ),
              TextButton(
                onPressed:
                    _busy ? null : () => _runAction(() => _remove(server)),
                style: TextButton.styleFrom(foregroundColor: Colors.red),
                child: const Text('Remove', style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  /// What the active node says about itself. Absent facts are simply not shown:
  /// a node with no peer-to-peer transport has no node id, which is not a fault.
  List<Widget> _activeDetails(ThemeData theme) {
    final scheme = theme.colorScheme;
    final labelStyle = TextStyle(fontSize: 11, color: scheme.onSurfaceVariant);

    if (_busy) {
      return const [
        SizedBox(height: 8),
        SizedBox(
          height: 2,
          child: LinearProgressIndicator(),
        ),
      ];
    }

    return [
      const SizedBox(height: 6),
      if (_info.version != null)
        Text('atomic-server ${_info.version}', style: labelStyle)
      else
        Text('Not reachable', style: labelStyle.copyWith(color: Colors.orange)),
      if (_info.nodeId != null) ...[
        const SizedBox(height: 4),
        InkWell(
          onTap: () => _copy(_info.nodeId!, 'Node ID'),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  _info.nodeId!,
                  style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              Icon(Icons.copy, size: 12, color: scheme.onSurfaceVariant),
            ],
          ),
        ),
      ],
      if (_usage != null) ...[
        const SizedBox(height: 6),
        Text(
          '${_usage!.resourceCount} resources · ${formatBytes(_usage!.totalBytes)}',
          style: labelStyle,
        ),
        if (_usage!.blobBytes > 0)
          Text(
            'files ${formatBytes(_usage!.blobBytes)} · edits ${formatBytes(_usage!.loroBytes)}',
            style: labelStyle.copyWith(fontSize: 10),
          ),
      ],
    ];
  }

  /// A paired device (Iroh peer), shown alongside the always-on ones. Live
  /// means it holds a connection right now; the green dot mirrors the browser.
  /// Below the name we show the node id (copyable, so it can be pasted into
  /// another device's "Connect by address") and when we last synced.
  Widget _peerCard(ThemeData theme, Map<String, String> peer) {
    final nodeId = peer['node_id'] ?? '';
    final name = (peer['name'] ?? '').trim();
    final label = name.isNotEmpty
        ? name
        : '${nodeId.substring(0, nodeId.length.clamp(0, 12))}…';
    final isLive = isLiveAtomicPeer(nodeId, _livePeerIds);
    final scheme = theme.colorScheme;
    final labelStyle = TextStyle(fontSize: 11, color: scheme.onSurfaceVariant);
    final lastSynced = int.tryParse(peer['last_synced'] ?? '');

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: scheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.phone_android,
                  size: 18, color: scheme.onSurfaceVariant),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  label,
                  style: const TextStyle(fontSize: 14),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: isLive
                      ? Colors.green.withValues(alpha: 0.15)
                      : scheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  isLive ? 'Connected' : 'Paired',
                  style: TextStyle(
                    fontSize: 10,
                    color: isLive
                        ? Colors.green.shade800
                        : scheme.onSurfaceVariant,
                  ),
                ),
              ),
              IconButton(
                icon: const Icon(Icons.close, size: 16),
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
                tooltip: 'Remove',
                onPressed: _busy
                    ? null
                    : () => _runAction(() async {
                          await widget.backend.removeKnownPeer(nodeId);
                          if (!mounted) return;
                          setState(() => _peers
                              .removeWhere((p) => p['node_id'] == nodeId));
                        }),
              ),
            ],
          ),
          if (nodeId.isNotEmpty) ...[
            const SizedBox(height: 6),
            InkWell(
              onTap: () => _copy(nodeId, 'Device ID'),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      nodeId,
                      style: const TextStyle(
                          fontSize: 10, fontFamily: 'monospace'),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Icon(Icons.copy, size: 12, color: scheme.onSurfaceVariant),
                ],
              ),
            ),
          ],
          const SizedBox(height: 4),
          Text(
            lastSynced != null
                ? 'Last synced ${_relativeTime(lastSynced)}'
                : 'Not synced yet',
            style: labelStyle,
          ),
        ],
      ),
    );
  }

  /// Coarse "2m ago" / "3h ago" / "5d ago" for a unix-millis timestamp — enough
  /// to tell "just now" from "days back" without a date library.
  String _relativeTime(int millis) {
    final delta =
        DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(millis));

    if (delta.inSeconds < 60) return 'just now';
    if (delta.inMinutes < 60) return '${delta.inMinutes}m ago';
    if (delta.inHours < 24) return '${delta.inHours}h ago';

    return '${delta.inDays}d ago';
  }

  /// Show a QR code for another device to scan, then reload so the freshly
  /// paired device appears in the list above.
  Future<void> _pairWithQr() async {
    try {
      await widget.backend.pair(context);
      if (mounted) await _load();
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    }
  }

  Widget _addButton() {
    return Wrap(
      spacing: 8,
      children: [
        TextButton.icon(
          onPressed: _pairWithQr,
          icon: const Icon(Icons.qr_code_2, size: 16),
          label:
              const Text('Pair with QR code', style: TextStyle(fontSize: 12)),
          style: TextButton.styleFrom(padding: EdgeInsets.zero),
        ),
        if (widget.backend.servers != null)
          TextButton.icon(
            onPressed: () => setState(() => _showAdd = true),
            icon: const Icon(Icons.add, size: 16),
            label: const Text('Connect by address',
                style: TextStyle(fontSize: 12)),
            style: TextButton.styleFrom(padding: EdgeInsets.zero),
          ),
      ],
    );
  }

  Widget _addField(ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _addController,
              autofocus: true,
              decoration: const InputDecoration(
                hintText: 'localhost:9883',
                border: OutlineInputBorder(),
                isDense: true,
              ),
              keyboardType: TextInputType.url,
              autocorrect: false,
              onSubmitted: (_) => _runAction(_add),
            ),
          ),
          const SizedBox(width: 8),
          TextButton(
            onPressed: _busy ? null : () => _runAction(_add),
            child: const Text('Add'),
          ),
          TextButton(
            onPressed: () => setState(() {
              _showAdd = false;
              _addController.clear();
            }),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }
}
