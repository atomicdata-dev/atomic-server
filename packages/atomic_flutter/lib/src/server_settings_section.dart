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

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'paired_device.dart';
import 'peer_details_sheet.dart';
import 'settings_backend.dart';
import 'device_stats.dart';
import 'server_info.dart';
import 'server_url.dart';
import 'sync_widgets.dart';
import 'theme.dart';

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
  List<Map<String, String>> _unsaved = [];
  String? _ownAgent;
  bool _loading = true;
  bool _busy = false;
  bool _showAdd = false;
  String? _error;
  final _addController = TextEditingController();

  /// What each listed server says about itself (`/server`), by URL: its node
  /// id is how a paired peer is recognised as that server.
  Map<String, ServerInfo> _infos = {};

  /// The device search, re-read while the section is shown.
  PeerSearchInfo? _search;
  Timer? _searchPoll;
  bool _showSearchDetail = false;
  bool _discovered = false;

  @override
  void initState() {
    super.initState();
    _search = widget.backend.peerSearchStatus();
    if (_search != null) {
      _searchPoll = Timer.periodic(const Duration(seconds: 2), (_) {
        final next = widget.backend.peerSearchStatus();
        if (!mounted) return;
        final liveChanged = next?.connected != _search?.connected;
        setState(() => _search = next);
        // A device came or went: its card's Connected / Paired badge too.
        if (liveChanged) {
          _refreshPeers();
        } else {
          _refreshUnsaved();
        }
      });
    }
    _load();
  }

  @override
  void dispose() {
    _searchPoll?.cancel();
    _addController.dispose();
    super.dispose();
  }

  /// Unpaired visitors, and a second device, come and go without the search
  /// state changing.
  Future<void> _refreshUnsaved() async {
    try {
      final live = await widget.backend.livePeerIds();
      final unsaved = await widget.backend.liveUnsavedPeers();
      if (!mounted) return;
      if (!setEquals(live, _livePeerIds)) setState(() => _livePeerIds = live);
      final same = unsaved.length == _unsaved.length &&
          [
            for (var i = 0; i < unsaved.length; i++)
              unsaved[i]['node_id'] == _unsaved[i]['node_id'] &&
                  unsaved[i]['name'] == _unsaved[i]['name']
          ].every((b) => b);
      if (!same) setState(() => _unsaved = unsaved);
    } catch (_) {}
  }

  Future<void> _refreshPeers() async {
    try {
      final peers = await widget.backend.getKnownPeers();
      final live = await widget.backend.livePeerIds();
      final unsaved = await widget.backend.liveUnsavedPeers();
      if (mounted) {
        setState(() {
          _peers = peers;
          _livePeerIds = live;
          _unsaved = unsaved;
        });
      }
    } catch (_) {}
  }

  /// Every listed server's own account of itself, in parallel; one that does
  /// not answer is simply unknown.
  Future<void> _loadServerInfos() async {
    final backend = widget.backend.servers;
    if (backend == null) return;
    final entries = await Future.wait(_servers.map((url) async {
      try {
        return MapEntry(url, await backend.serverInfo(url));
      } catch (_) {
        return MapEntry(url, ServerInfo.unknown);
      }
    }));
    if (mounted) setState(() => _infos = Map.fromEntries(entries));
  }

  /// Servers the active drive's pkarr record names (verified by the host),
  /// once per section: they join the list without being typed in.
  Future<void> _discoverServers() async {
    final backend = widget.backend.servers;
    if (backend == null || _discovered) return;
    _discovered = true;
    try {
      final found = await backend.discoverServers();
      if (!mounted) return;
      if (found.any((url) => !_servers.any((s) => sameOrigin(s, url)))) {
        await _load();
      }
    } catch (_) {}
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
      List<Map<String, String>> unsaved = [];
      try {
        peers = await widget.backend.getKnownPeers();
        livePeerIds = await widget.backend.livePeerIds();
        unsaved = await widget.backend.liveUnsavedPeers();
      } catch (_) {
        // no peers available
      }
      // Whose device a peer is, when the host recorded its agent.
      String? ownAgent;
      try {
        ownAgent = (await widget.backend.getActiveAgent())?.subject;
      } catch (_) {}

      if (!mounted) return;

      setState(() {
        _servers = servers;
        _active = active;
        _peers = peers;
        _livePeerIds = livePeerIds;
        _unsaved = unsaved;
        _ownAgent = ownAgent;
        _loading = false;
      });

      await _loadActiveDetails();
      await _loadServerInfos();
      unawaited(_discoverServers());
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

  /// The raw id is long and unreadable, so it is not shown: a compact button
  /// copies it (the tooltip shows it).
  Widget _copyIdButton(String id, String label) => Tooltip(
        message: id,
        child: SyncTextAction(
          label: 'Copy ID',
          icon: Icons.copy,
          onPressed: () => _copy(id, 'ID'),
        ),
      );

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);

    if (_loading) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: SyncGap.l),
        child: Center(child: CircularProgressIndicator()),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: SyncGap.m),
        const SyncHeader('Devices'),
        if (_search != null) _searchStatus(c, _search!),
        if (_servers.isEmpty && _peers.isEmpty)
          Padding(
            padding: const EdgeInsets.only(bottom: SyncGap.s),
            child: SyncNote(
              widget.backend.servers == null
                  ? 'No other devices yet. Pair one below.'
                  : 'No other devices yet. Pair one below, or add an always-on device by address.',
            ),
          ),
        for (final server in _servers) _serverCard(c, server),
        for (final peer in _peers)
          if (!_servers.any((s) => _isServerPeer(s, peer))) _peerCard(c, peer),
        if (_unsaved.isNotEmpty) ...[
          const SizedBox(height: SyncGap.s),
          const SyncHeader('Connected now'),
          for (final peer in _unsaved) _unsavedCard(c, peer),
        ],
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(bottom: SyncGap.s),
            child: SyncNote(_error!,
                tone: SyncTone.error, icon: Icons.error_outline),
          ),
        const SizedBox(height: SyncGap.xs),
        if (_showAdd) _addField(c) else _addButton(),
      ],
    );
  }

  /// Whether a paired device *is* this server: the same always-on device
  /// reached two ways, over https and over Iroh. Pairing with a server's code
  /// names the peer after it (`atomic.place (node1.example.org)`), and the
  /// active server reports its own node id. One device is listed once.
  ///
  /// A server introduces itself (HELLO) by its configured name, often its
  /// host's first label (`staging` for staging.atomicdata.dev), and its
  /// `/server` names its node id — when it tells this device (a node may
  /// hide it from a visitor). Any of those makes the peer that server.
  bool _isServerPeer(String server, Map<String, String> peer) {
    final host = Uri.tryParse(server)?.host.toLowerCase() ?? '';
    final name = (peer['name'] ?? '').trim().toLowerCase();
    if (host.isNotEmpty && name.isNotEmpty) {
      if (name.contains(host) || name == host.split('.').first) return true;
    }
    final nodeId = _infos[server]?.nodeId ??
        (sameOrigin(server, _active) ? _info.nodeId : null);
    return nodeId != null && isLiveAtomicPeer(peer['node_id'] ?? '', {nodeId});
  }

  /// A peer that is a server whose address this device does not know: an
  /// atomic-server names itself `…atomic-server` unless configured otherwise.
  /// Shown as a server, not as a phone.
  static bool _looksLikeServer(Map<String, String> peer) =>
      (peer['name'] ?? '').trim().toLowerCase().endsWith('atomic-server');

  /// The search's line ("Looking for devices…", "No other device found yet"),
  /// a "Search again" button and, on tap, why.
  Widget _searchStatus(AppColors c, PeerSearchInfo search) {
    final style = search.failed
        ? SyncText.caption(c).copyWith(color: SyncTone.warning.color(c))
        : SyncText.caption(c);
    final again = widget.backend.searchAgain;
    final detail = search.detail;
    return Padding(
      key: const ValueKey('peer-search-status'),
      padding: const EdgeInsets.only(bottom: SyncGap.s),
      child: SyncCard(
        padding: const EdgeInsets.symmetric(
            horizontal: SyncGap.l, vertical: SyncGap.xs),
        children: [
          ConstrainedBox(
            constraints: const BoxConstraints(minHeight: 48),
            child: Row(
              children: [
                if (search.busy)
                  const Padding(
                    padding: EdgeInsets.only(right: SyncGap.m),
                    child: SyncSpinner(),
                  ),
                Expanded(
                  child: InkWell(
                    mouseCursor: WidgetStateMouseCursor.clickable,
                    onTap: detail == null
                        ? null
                        : () => setState(
                            () => _showSearchDetail = !_showSearchDetail),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: SyncGap.s),
                      child: Text(
                        [
                          search.message,
                          if (!search.busy &&
                              !search.connected &&
                              (search.retryInSecs ?? 0) > 0)
                            'trying again in ${search.retryInSecs} s',
                        ].join(' · '),
                        style: style,
                      ),
                    ),
                  ),
                ),
                if (again != null && !search.busy)
                  SyncTextAction(
                    label: 'Search again',
                    onPressed: () {
                      again();
                      setState(
                          () => _search = widget.backend.peerSearchStatus());
                    },
                  ),
              ],
            ),
          ),
          if (detail != null && (_showSearchDetail || search.failed))
            Padding(
              padding: const EdgeInsets.only(bottom: SyncGap.s),
              child: Text(detail, style: style),
            ),
        ],
      ),
    );
  }

  Widget _serverCard(AppColors c, String server) {
    final peer = _peers.where((p) => _isServerPeer(server, p)).firstOrNull;
    final peerSynced = int.tryParse(peer?['last_synced'] ?? '');
    final isActive = sameOrigin(server, _active);

    return Padding(
      padding: const EdgeInsets.only(bottom: SyncGap.s),
      child: SyncCard(
        padding: const EdgeInsets.all(SyncGap.l),
        children: [
          Row(
            children: [
              Icon(isActive ? Icons.cloud_done : Icons.cloud_outlined,
                  size: 24, color: isActive ? c.main : c.textSecondary),
              const SizedBox(width: SyncGap.m),
              Expanded(
                child: Text(
                  serverLabel(server),
                  style: isActive ? SyncText.bodyStrong(c) : SyncText.body(c),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (isActive) const StatusChip('In use', tone: SyncTone.info),
            ],
          ),
          _serverAddressLine(c, server, peer, showId: !isActive),
          if (isActive) ..._activeDetails(c),
          if (peer != null)
            Padding(
              padding: const EdgeInsets.only(top: SyncGap.xs),
              child: Text(
                [
                  if (isLiveAtomicPeer(peer['node_id'] ?? '', _livePeerIds))
                    'Connected'
                  else
                    'Paired',
                  if (peerSynced != null)
                    'last synced ${relativeTime(peerSynced)}',
                ].join(' · '),
                style: SyncText.caption(c),
              ),
            ),
          Align(
            alignment: Alignment.centerRight,
            child: Wrap(
              alignment: WrapAlignment.end,
              children: [
                if (isActive)
                  SyncTextAction(
                    label: 'Sync workspace here',
                    onPressed: _busy ? null : _pushWorkspace,
                  ),
                if (!isActive)
                  SyncTextAction(
                    label: 'Switch to this',
                    onPressed: _busy ? null : () => _switchTo(server),
                  ),
                SyncActionButton(
                  label: 'Remove',
                  kind: SyncButtonKind.destructive,
                  onPressed:
                      _busy ? null : () => _runAction(() => _remove(server)),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  /// Where the server is known: its https URL, with a Copy ID button for its
  /// node id (from its `/server`, else from the paired peer that is it). The
  /// active server's id is shown in its details below instead.
  Widget _serverAddressLine(
      AppColors c, String server, Map<String, String>? peer,
      {required bool showId}) {
    final nodeId = _infos[server]?.nodeId ?? peer?['node_id'];
    return Row(
      children: [
        Expanded(
          child: Text(server,
              style: SyncText.caption(c), overflow: TextOverflow.ellipsis),
        ),
        if (showId && nodeId != null && nodeId.isNotEmpty)
          _copyIdButton(nodeId, 'Node ID'),
      ],
    );
  }

  /// What the active node says about itself. Absent facts are simply not shown:
  /// a node with no peer-to-peer transport has no node id, which is not a fault.
  List<Widget> _activeDetails(AppColors c) {
    final labelStyle = SyncText.caption(c);

    if (_busy) {
      return const [
        SizedBox(height: SyncGap.s),
        SizedBox(height: 2, child: LinearProgressIndicator()),
      ];
    }

    return [
      const SizedBox(height: SyncGap.xs),
      Row(
        children: [
          Expanded(
            child: _info.version != null
                ? Text('atomic-server ${_info.version}', style: labelStyle)
                : Text('Not reachable',
                    style:
                        labelStyle.copyWith(color: SyncTone.warning.color(c))),
          ),
          if (_info.nodeId != null) _copyIdButton(_info.nodeId!, 'Node ID'),
        ],
      ),
      if (_usage != null) ...[
        const SizedBox(height: SyncGap.xs),
        Text(
          '${_usage!.resourceCount} resources · ${formatBytes(_usage!.totalBytes)}',
          style: labelStyle,
        ),
        if (_usage!.blobBytes > 0)
          Text(
            'files ${formatBytes(_usage!.blobBytes)} · edits ${formatBytes(_usage!.loroBytes)}',
            style: labelStyle,
          ),
      ],
    ];
  }

  /// A device that is connected to us but not paired (it scanned our QR).
  /// Display only: no actions, and nothing is saved about it.
  Widget _unsavedCard(AppColors c, Map<String, String> peer) {
    final nodeId = peer['node_id'] ?? '';
    final shortId = '${nodeId.substring(0, nodeId.length.clamp(0, 12))}…';
    final name = (peer['name'] ?? '').trim();

    return Padding(
      padding: const EdgeInsets.only(bottom: SyncGap.s),
      child: SyncCard(
        padding: const EdgeInsets.all(SyncGap.l),
        children: [
          Row(
            children: [
              Icon(Icons.phone_android, size: 24, color: c.textSecondary),
              const SizedBox(width: SyncGap.m),
              Expanded(
                child: Text(name.isNotEmpty ? name : shortId,
                    style: SyncText.body(c), overflow: TextOverflow.ellipsis),
              ),
            ],
          ),
          Text('$shortId · Connected to you · not saved',
              key: const ValueKey('unsaved-peer-caption'),
              style: SyncText.caption(c)),
        ],
      ),
    );
  }

  /// A paired device (Iroh peer), shown alongside the always-on ones. Live
  /// means it holds a connection right now. Below the name we show when we
  /// last synced and, because no peer reports how much of the data it holds
  /// yet, say so rather than guess.
  Widget _peerCard(AppColors c, Map<String, String> peer) {
    final device = PairedDevice.fromRow(peer, ownAgent: _ownAgent);
    final nodeId = device.nodeId;
    final isLive = isLiveAtomicPeer(nodeId, _livePeerIds);
    final lastSynced = device.lastSynced;
    final isServer = _looksLikeServer(peer);
    final relay = Uri.tryParse(device.relayUrl ?? '')?.host ?? '';
    final relation = device.relationLabel;

    return Padding(
      padding: const EdgeInsets.only(bottom: SyncGap.s),
      child: InkWell(
        mouseCursor: WidgetStateMouseCursor.clickable,
        key: ValueKey('peer-card-$nodeId'),
        borderRadius: BorderRadius.circular(12),
        onTap: () => _openPeer(device),
        child: SyncCard(
          padding: const EdgeInsets.all(SyncGap.l),
          children: [
            Row(
              children: [
                _peerAvatar(c, device, isServer: isServer),
                const SizedBox(width: SyncGap.m),
                Expanded(
                  child: Text(device.label,
                      style: SyncText.body(c), overflow: TextOverflow.ellipsis),
                ),
                StatusChip(isLive ? 'Connected' : 'Paired',
                    tone: isLive ? SyncTone.success : SyncTone.neutral),
                IconButton(
                  icon: const Icon(Icons.close, size: 20),
                  color: c.textSecondary,
                  constraints:
                      const BoxConstraints(minWidth: 48, minHeight: 48),
                  tooltip: 'Remove',
                  onPressed: _busy ? null : () => _forgetPeer(nodeId),
                ),
              ],
            ),
            if (relation != null)
              Padding(
                padding: const EdgeInsets.only(bottom: SyncGap.xs),
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: StatusChip(relation,
                      icon: device.isOtherPerson
                          ? Icons.people_outline
                          : Icons.devices_outlined),
                ),
              ),
            Row(
              children: [
                Expanded(
                  child: Text(
                    [
                      if (isServer) 'Server, address unknown',
                      // Connected devices exchange every change as it is
                      // made; a stamp only comes from a full sync round.
                      if (isLive)
                        'Up to date, syncing live'
                      else if (lastSynced != null)
                        'Last synced ${relativeTime(lastSynced)}'
                      else
                        'Not synced yet',
                      if (relay.isNotEmpty)
                        'via ${relay.replaceAll(RegExp(r'\.$'), '')}',
                    ].join(' · '),
                    style: SyncText.caption(c),
                  ),
                ),
                if (nodeId.isNotEmpty) _copyIdButton(nodeId, 'Device ID'),
              ],
            ),
            if (!isServer)
              Padding(
                padding: const EdgeInsets.only(bottom: SyncGap.xs),
                child: Text('Data size unknown',
                    key: const ValueKey('peer-data-size-unknown'),
                    style: SyncText.caption(c)),
              ),
          ],
        ),
      ),
    );
  }

  /// A person's initials for someone else's device; a device icon for yours.
  Widget _peerAvatar(AppColors c, PairedDevice device,
      {required bool isServer}) {
    if (device.isOtherPerson) {
      return CircleAvatar(
        key: const ValueKey('peer-person-avatar'),
        radius: 14,
        backgroundColor: c.bg2,
        child: Text(device.initials,
            style: SyncText.chip(c.textPrimary).copyWith(fontSize: 11)),
      );
    }
    return Icon(isServer ? Icons.cloud_outlined : Icons.phone_android,
        size: 24, color: c.textSecondary);
  }

  Future<void> _forgetPeer(String nodeId) => _runAction(() async {
        await widget.backend.removeKnownPeer(nodeId);
        if (!mounted) return;
        setState(() => _peers.removeWhere((p) => p['node_id'] == nodeId));
      });

  /// The device's details: who, its id, the last sync, and what to do.
  Future<void> _openPeer(PairedDevice device) async {
    final forget = await showModalBottomSheet<bool>(
      context: context,
      showDragHandle: true,
      isScrollControlled: true,
      builder: (_) => PeerDetailsSheet(
        device: device,
        live: isLiveAtomicPeer(device.nodeId, _livePeerIds),
        syncPeer: widget.backend.syncPeer,
      ),
    );
    if (forget == true) {
      await _forgetPeer(device.nodeId);
    } else {
      await _refreshPeers();
    }
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
      spacing: SyncGap.s,
      runSpacing: SyncGap.s,
      children: [
        SyncActionButton(
          label: 'Pair with QR code',
          icon: Icons.qr_code_2,
          kind: SyncButtonKind.primary,
          onPressed: _pairWithQr,
        ),
        if (widget.backend.servers != null)
          SyncActionButton(
            label: 'Connect by address',
            icon: Icons.add,
            onPressed: () => setState(() => _showAdd = true),
          ),
      ],
    );
  }

  Widget _addField(AppColors c) {
    return Row(
      children: [
        Expanded(
          child: TextField(
            controller: _addController,
            autofocus: true,
            style: SyncText.body(c),
            decoration: InputDecoration(
              hintText: 'localhost:9883',
              hintStyle: SyncText.caption(c),
              isDense: true,
              contentPadding: const EdgeInsets.symmetric(
                  horizontal: SyncGap.m, vertical: SyncGap.m),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide(color: c.bg2),
              ),
            ),
            keyboardType: TextInputType.url,
            autocorrect: false,
            onSubmitted: (_) => _runAction(_add),
          ),
        ),
        const SizedBox(width: SyncGap.s),
        SyncTextAction(
          label: 'Add',
          onPressed: _busy ? null : () => _runAction(_add),
        ),
        SyncTextAction(
          label: 'Cancel',
          onPressed: () => setState(() {
            _showAdd = false;
            _addController.clear();
          }),
        ),
      ],
    );
  }
}
