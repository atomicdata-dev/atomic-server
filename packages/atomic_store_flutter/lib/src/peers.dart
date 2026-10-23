import 'dart:async';
import 'dart:convert';

import '../bridge/api/node.dart' as bridge;
import '../bridge/api/resources.dart' as bridge;
import '../bridge/api/simple/peers.dart' as free;
import '../bridge/api/simple/sync.dart' as free;
import 'bridge_store_backend.dart' show storeExceptionFromBridge;
import '../bridge/api/error.dart' as bridge;
import 'pairing.dart';

/// A device this node has paired with.
class KnownPeer {
  const KnownPeer({
    required this.nodeId,
    this.name = '',
    this.lastSynced,
    this.lastSent,
    this.lastReceived,
    this.live = false,
  });

  /// The Iroh node id (64 hex characters).
  final String nodeId;

  /// The name of the device; empty when neither you nor it gave one.
  final String name;

  /// When a sync with it last finished, `null` if never.
  final DateTime? lastSynced;

  /// Resources the last sync sent to / got from it.
  final int? lastSent;
  final int? lastReceived;

  /// Connected right now.
  final bool live;

  KnownPeer copyWith({bool? live, String? name}) => KnownPeer(
      nodeId: nodeId,
      name: name ?? this.name,
      lastSynced: lastSynced,
      lastSent: lastSent,
      lastReceived: lastReceived,
      live: live ?? this.live);

  @override
  bool operator ==(Object other) =>
      other is KnownPeer &&
      other.nodeId == nodeId &&
      other.name == name &&
      other.lastSynced == lastSynced &&
      other.lastSent == lastSent &&
      other.lastReceived == lastReceived &&
      other.live == live;

  @override
  int get hashCode =>
      Object.hash(nodeId, name, lastSynced, lastSent, lastReceived, live);

  @override
  String toString() => 'KnownPeer($nodeId, "$name", live: $live)';
}

/// A device connected right now that is not paired.
class LivePeer {
  const LivePeer(this.nodeId, [this.name = '']);
  final String nodeId;
  final String name;

  @override
  bool operator ==(Object other) =>
      other is LivePeer && other.nodeId == nodeId && other.name == name;

  @override
  int get hashCode => Object.hash(nodeId, name);
}

/// What one sync with one device did.
class PeerSyncResult {
  const PeerSyncResult({
    required this.imported,
    required this.pushed,
    required this.inSync,
    this.peerName,
  });

  /// Resources received / sent.
  final int imported;
  final int pushed;

  /// Both sides already had everything.
  final bool inSync;

  /// The name the device announced.
  final String? peerName;
}

/// What syncing with all paired and connected devices did.
class PeersSyncResult {
  const PeersSyncResult(
      {required this.imported,
      required this.answered,
      this.failures = const []});
  final int imported;

  /// Devices that answered.
  final int answered;

  /// One line per device that did not.
  final List<String> failures;
}

/// Something happened with a device (the process's sync events).
class PeerEvent {
  const PeerEvent(
      {required this.nodeId,
      required this.kind,
      this.resourcesImported = 0,
      this.at});

  final String nodeId;

  /// `sync` (a sync finished), `connected` or `disconnected`.
  final String kind;
  final int resourcesImported;
  final DateTime? at;

  static PeerEvent? fromJson(Object? json) {
    if (json is! Map) return null;
    final ts = json['timestamp'];
    return PeerEvent(
      nodeId: '${json['remote_node_id'] ?? ''}',
      kind: '${json['kind'] ?? 'sync'}',
      resourcesImported: (json['resources_imported'] as num?)?.toInt() ?? 0,
      at: ts is num ? DateTime.fromMillisecondsSinceEpoch(ts.toInt()) : null,
    );
  }
}

/// What the background search for the account's other devices is doing.
class PeerSearchStatus {
  const PeerSearchStatus(this.state, [this.message = '']);

  /// `starting`, `searching`, `no_peers_yet`, `connected` or `failed`;
  /// empty when unknown.
  final String state;
  final String message;

  static PeerSearchStatus fromJson(String json) {
    try {
      final map = jsonDecode(json) as Map<String, dynamic>;
      return PeerSearchStatus(
          '${map['state'] ?? ''}', '${map['message'] ?? ''}');
    } catch (_) {
      return const PeerSearchStatus('');
    }
  }
}

/// Sync between devices, over Iroh (QUIC): pair two devices with a QR code,
/// and they keep each other's drive up to date while both are online. No
/// server involved.
///
/// **Peers belong to the process.** Iroh runs one endpoint per process and it
/// serves one store: the one of the first node that calls [start]. Another
/// node in the same process gets an error from [start]. Open one node (as
/// `AtomicFlutter.open` asks anyway) and use its [Peers].
///
/// ```dart
/// final id = await node.peers.start();
/// showQr(node.peers.pairingCode);                 // device A
/// await node.peers.pair(scannedText);             // device B
/// node.peers.watchLive().listen(print);
/// ```
abstract interface class Peers {
  /// Starts the peer (once per process) and returns this device's node id.
  /// Also starts the background search for the account's other devices.
  /// Throws when another node's store already owns the peer.
  Future<String> start();

  /// This device's node id once [start] ran, else `null`.
  String? get nodeId;

  /// The text to show as a QR code for other devices to scan
  /// ([PairingCode.format] of [nodeId] and [deviceName]); `null` before
  /// [start].
  String? get pairingCode;

  /// The name other devices see.
  String get deviceName;
  set deviceName(String name);

  /// Pairs with the device in a scanned or pasted [code] (see
  /// [PairingCode.parse]) and syncs the node's drive with it. Remembers the
  /// device only when the sync worked. Throws [FormatException] for a text
  /// that is no pairing code, and a `StoreException` when the device cannot
  /// be reached.
  Future<PeerSyncResult> pair(String code);

  /// Syncs the node's drive with the device [nodeId] now, in both directions.
  Future<PeerSyncResult> syncWith(String nodeId);

  /// Syncs with every paired and connected device now.
  Future<PeersSyncResult> syncNow();

  /// The paired devices, most recently synced first.
  List<KnownPeer> get known;

  /// [known] now and after every change made here, a sync or a device
  /// connecting or leaving.
  Stream<List<KnownPeer>> watchKnown();

  /// Remembers a paired device (no sync). A non-empty [name] renames it.
  void add(String nodeId, [String name = '']);

  /// Gives a paired device another name.
  void rename(String nodeId, String name);

  /// Forgets a paired device.
  void remove(String nodeId);

  /// The ids of the devices connected now.
  Set<String> get liveIds;

  /// Devices connected now that are not paired (display only).
  List<LivePeer> get livePeers;

  /// The ids of connected devices now and each time their number changes.
  Stream<Set<String>> watchLive();

  /// Syncs and connections of devices, as they happen.
  Stream<PeerEvent> get events;

  /// What the search for the account's other devices is doing.
  PeerSearchStatus get searchStatus;

  /// Looks for the other devices now.
  void searchAgain();

  /// Tell the peer whether the app is in the foreground; in the background
  /// the search stops. Call from the app lifecycle (resumed: true; paused,
  /// hidden, detached: false).
  void setForeground(bool foreground);
}

/// [Peers] over the bridge: the node's handle for what belongs to its store,
/// the process-wide functions for what belongs to the endpoint.
class BridgePeers implements Peers {
  BridgePeers(this._handle);

  final bridge.AtomicStore _handle;
  final _changed = StreamController<void>.broadcast();

  Future<T> _guardAsync<T>(Future<T> Function() run) async {
    try {
      return await run();
    } on bridge.AtomicError catch (e) {
      throw storeExceptionFromBridge(e);
    }
  }

  @override
  Future<String> start() => _guardAsync(() => _handle.startPeer());

  @override
  String? get nodeId => free.getPeerId();

  @override
  String? get pairingCode {
    final id = nodeId;
    return id == null ? null : PairingCode.format(id, deviceName);
  }

  @override
  String get deviceName => _handle.deviceName();

  @override
  set deviceName(String name) => _handle.setDeviceName(name: name);

  @override
  Future<PeerSyncResult> pair(String code) async {
    final parsed = PairingCode.parse(code);
    if (parsed == null) {
      throw const FormatException('This is not an Atomic pairing code');
    }
    if (nodeId == null) await start();
    final result = await syncWith(parsed.nodeId);
    add(parsed.nodeId,
        parsed.name.isNotEmpty ? parsed.name : result.peerName ?? '');
    return result;
  }

  @override
  Future<PeerSyncResult> syncWith(String nodeId) async {
    final r = await _guardAsync(() => _handle.syncWithPeer(nodeId: nodeId));
    _changed.add(null);
    return peerSyncResultFromBridge(r);
  }

  @override
  Future<PeersSyncResult> syncNow() async {
    final r = await _guardAsync(() => _handle.syncWithPeers());
    _changed.add(null);
    return PeersSyncResult(
        imported: r.imported, answered: r.answered, failures: r.failures);
  }

  @override
  List<KnownPeer> get known {
    final live = liveIds;
    return knownPeersFromBridge(_handle.knownPeers(), live);
  }

  @override
  Stream<List<KnownPeer>> watchKnown() {
    late final StreamController<List<KnownPeer>> controller;
    StreamSubscription<void>? changes;
    StreamSubscription<Set<String>>? live;
    controller = StreamController<List<KnownPeer>>(
      onListen: () {
        controller.add(known);
        changes = _changed.stream.listen((_) => controller.add(known));
        live = watchLive().listen((_) => controller.add(known));
      },
      onCancel: () async {
        await changes?.cancel();
        await live?.cancel();
      },
    );
    return controller.stream;
  }

  @override
  void add(String nodeId, [String name = '']) {
    _handle.addKnownPeer(nodeId: nodeId, name: name);
    _changed.add(null);
  }

  @override
  void rename(String nodeId, String name) => add(nodeId, name);

  @override
  void remove(String nodeId) {
    _handle.removeKnownPeer(nodeId: nodeId);
    _changed.add(null);
  }

  @override
  Set<String> get liveIds => free.livePeerIds().toSet();

  @override
  List<LivePeer> get livePeers =>
      [for (final p in _handle.liveUnpairedPeers()) LivePeer(p.nodeId, p.name)];

  @override
  Stream<Set<String>> watchLive() {
    var cancelled = false;
    late final StreamController<Set<String>> controller;
    Future<void> run() async {
      var count = free.livePeerCount();
      controller.add(liveIds);
      while (!cancelled) {
        // Returns when the number of connected devices differs from `count`.
        count = await free.waitForPeerCountChange(current: count);
        if (!cancelled) controller.add(liveIds);
      }
    }

    controller = StreamController<Set<String>>(
      onListen: () => unawaited(run()),
      onCancel: () => cancelled = true,
    );
    return controller.stream;
  }

  @override
  Stream<PeerEvent> get events {
    var cancelled = false;
    late final StreamController<PeerEvent> controller;
    Future<void> run() async {
      while (!cancelled) {
        final json = await free.waitForSyncEvent(); // "null" after 60 s quiet
        if (cancelled) return;
        try {
          final event = PeerEvent.fromJson(jsonDecode(json));
          if (event != null) {
            _changed.add(null);
            controller.add(event);
          }
        } catch (_) {}
      }
    }

    controller = StreamController<PeerEvent>(
      onListen: () => unawaited(run()),
      onCancel: () => cancelled = true,
    );
    return controller.stream;
  }

  @override
  PeerSearchStatus get searchStatus =>
      PeerSearchStatus.fromJson(free.peerSearchStatus());

  @override
  void searchAgain() => free.peerSearchAgain();

  @override
  void setForeground(bool foreground) =>
      free.setAppForeground(foreground: foreground);
}

/// Bridge rows to [KnownPeer]s, most recently synced first.
List<KnownPeer> knownPeersFromBridge(
    Iterable<bridge.KnownPeerInfo> rows, Set<String> liveIds) {
  final peers = [
    for (final p in rows)
      KnownPeer(
        nodeId: p.nodeId,
        name: p.name,
        lastSynced: p.lastSynced == null
            ? null
            : DateTime.fromMillisecondsSinceEpoch(p.lastSynced!.toInt()),
        lastSent: p.lastSent,
        lastReceived: p.lastReceived,
        live: liveIds.contains(p.nodeId),
      )
  ];
  peers.sort((a, b) => (b.lastSynced?.millisecondsSinceEpoch ?? 0)
      .compareTo(a.lastSynced?.millisecondsSinceEpoch ?? 0));
  return peers;
}

PeerSyncResult peerSyncResultFromBridge(bridge.PeerSyncOutcome r) =>
    PeerSyncResult(
        imported: r.imported,
        pushed: r.pushed,
        inSync: r.inSync,
        peerName: r.peerName);
