import 'dart:async';

import 'package:atomic_store/atomic_store.dart';

import 'atomic_flutter.dart' show AtomicParts;
import 'sharing.dart';
import 'src_exports.dart';

/// [value] now, then again after every event of [changes]. (Not `async*`: such
/// a stream cannot be cancelled while it waits for the next event.)
Stream<T> _current<T>(T Function() value, Stream<Object?> changes) {
  StreamSubscription<Object?>? sub;
  late final StreamController<T> controller;
  controller = StreamController<T>(
    onListen: () {
      controller.add(value());
      sub = changes.listen((_) => controller.add(value()));
    },
    onCancel: () => sub?.cancel(),
  );
  return controller.stream;
}

/// [Peers] in memory, for tests of an app's pairing and device screens. No
/// network: devices "answer" when you [reachable] them.
///
/// ```dart
/// final peers = FakePeers(deviceName: 'Test phone');
/// await peers.start();
/// peers.reachable.add(otherId);
/// await peers.pair(PairingCode.format(otherId, 'Laptop'));
/// expect(peers.known.single.name, 'Laptop');
/// peers.connect(otherId);                          // it shows as live
/// ```
class FakePeers implements Peers {
  FakePeers({this.deviceName = 'Fake device', String? nodeId})
      : _nodeId = nodeId,
        _startId = nodeId ?? 'f' * 64;

  final String _startId;
  String? _nodeId;
  final Map<String, KnownPeer> _known = {};
  final Set<String> _live = {};
  final _changed = StreamController<void>.broadcast();
  final _events = StreamController<PeerEvent>.broadcast();

  /// Node ids that answer a sync; any other one fails like an offline device.
  final Set<String> reachable = {};

  /// What [syncWith] reports for a reachable device.
  PeerSyncResult result =
      const PeerSyncResult(imported: 1, pushed: 0, inSync: false);

  /// Every sync asked for, in order.
  final List<String> syncs = [];

  /// The search status [searchStatus] returns.
  PeerSearchStatus status = const PeerSearchStatus('no_peers_yet');

  bool foreground = true;
  int searches = 0;

  @override
  String deviceName;

  @override
  Future<String> start() async => _nodeId ??= _startId;

  @override
  String? get nodeId => _nodeId;

  @override
  String? get pairingCode =>
      _nodeId == null ? null : PairingCode.format(_nodeId!, deviceName);

  @override
  Future<PeerSyncResult> pair(String code) async {
    final parsed = PairingCode.parse(code);
    if (parsed == null) {
      throw const FormatException('This is not an Atomic pairing code');
    }
    await start();
    final r = await syncWith(parsed.nodeId);
    add(parsed.nodeId, parsed.name.isNotEmpty ? parsed.name : r.peerName ?? '');
    _markSynced(parsed.nodeId);
    return r;
  }

  @override
  Future<PeerSyncResult> syncWith(String nodeId) async {
    syncs.add(nodeId);
    if (!reachable.contains(nodeId)) {
      throw const StoreException(
          StoreErrorKind.network, 'The device did not answer');
    }
    _markSynced(nodeId);
    return result;
  }

  void _markSynced(String nodeId) {
    final known = _known[nodeId];
    if (known != null) {
      _known[nodeId] = KnownPeer(
          nodeId: nodeId,
          name: known.name,
          lastSynced: DateTime.now(),
          lastSent: result.pushed,
          lastReceived: result.imported);
    }
    _changed.add(null);
  }

  @override
  Future<PeersSyncResult> syncNow() async {
    var imported = 0;
    var answered = 0;
    final failures = <String>[];
    for (final id in {..._known.keys, ..._live}) {
      try {
        imported += (await syncWith(id)).imported;
        answered++;
      } on StoreException catch (e) {
        failures.add('${id.substring(0, 12)}: ${e.message}');
      }
    }
    return PeersSyncResult(
        imported: imported, answered: answered, failures: failures);
  }

  @override
  List<KnownPeer> get known => [
        for (final p in _known.values)
          p.copyWith(live: _live.contains(p.nodeId))
      ]..sort((a, b) => (b.lastSynced?.millisecondsSinceEpoch ?? 0)
          .compareTo(a.lastSynced?.millisecondsSinceEpoch ?? 0));

  @override
  Stream<List<KnownPeer>> watchKnown() =>
      _current(() => known, _changed.stream);

  @override
  void add(String nodeId, [String name = '']) {
    final old = _known[nodeId];
    _known[nodeId] = old == null
        ? KnownPeer(nodeId: nodeId, name: name)
        : old.copyWith(name: name.isEmpty ? old.name : name);
    _changed.add(null);
  }

  @override
  void rename(String nodeId, String name) => add(nodeId, name);

  @override
  void remove(String nodeId) {
    _known.remove(nodeId);
    _changed.add(null);
  }

  @override
  Set<String> get liveIds => Set.unmodifiable(_live);

  @override
  List<LivePeer> get livePeers => [
        for (final id in _live)
          if (!_known.containsKey(id)) LivePeer(id)
      ];

  @override
  Stream<Set<String>> watchLive() => _current(() => liveIds, _changed.stream);

  @override
  Stream<PeerEvent> get events => _events.stream;

  @override
  PeerSearchStatus get searchStatus => status;

  @override
  void searchAgain() => searches++;

  @override
  void setForeground(bool foreground) => this.foreground = foreground;

  /// A device connects (a `connected` event, and it shows in [liveIds]).
  void connect(String nodeId) {
    _live.add(nodeId);
    _events
        .add(PeerEvent(nodeId: nodeId, kind: 'connected', at: DateTime.now()));
    _changed.add(null);
  }

  /// A device leaves.
  void disconnect(String nodeId) {
    _live.remove(nodeId);
    _events.add(
        PeerEvent(nodeId: nodeId, kind: 'disconnected', at: DateTime.now()));
    _changed.add(null);
  }
}

/// [ServerSync] in memory: a server that is reachable or not.
class FakeServerSync implements ServerSync {
  FakeServerSync({this.hasDrive = true});

  /// Origins that accept a [connect]; others throw a network error.
  final Set<String> servers = {};

  /// Origins [discover] and [verifiedOrigins] return for any drive.
  final List<String> hosting = [];

  /// Whether the node's drive is on the device after connecting ([resume]).
  bool hasDrive;

  SyncStatus _status = const SyncStatus();
  final _changes = StreamController<SyncStatus>.broadcast();
  int pushes = 0;

  @override
  List<String> log = [];

  @override
  SyncStatus get status => _status;

  void _set(SyncStatus s) {
    _status = s;
    _changes.add(s);
  }

  @override
  Stream<SyncStatus> watchStatus() => _current(() => _status, _changes.stream);

  @override
  Future<void> connect(String origin) async {
    if (!servers.contains(origin)) {
      throw StoreException(StoreErrorKind.network, '$origin did not answer');
    }
    _set(SyncStatus(connected: true, origin: origin));
  }

  @override
  Future<void> disconnect() async =>
      _set(SyncStatus(connected: false, origin: _status.origin));

  @override
  Future<ResumeStatus> resume(String? origin,
      {Duration timeout = const Duration(seconds: 10)}) async {
    var reached = true;
    if (origin != null && origin.trim().isNotEmpty) {
      try {
        await connect(origin.trim());
      } on StoreException {
        reached = false;
      }
    }
    if (hasDrive) return ResumeStatus.ready;
    return reached ? ResumeStatus.needsSync : ResumeStatus.offline;
  }

  @override
  Future<bool> pushPending() async {
    pushes++;
    return _status.connected;
  }

  @override
  Future<List<String>> verifiedOrigins(String drive) async => List.of(hosting);

  @override
  Future<String?> discover(String drive) async {
    if (hosting.isEmpty) return null;
    await connect(hosting.first);
    return hosting.first;
  }
}

/// [Drives] in memory, bound to a [Store] so `store.drive` follows.
class FakeDrives implements Drives {
  FakeDrives(this._store, [Iterable<DriveInfo> drives = const []]) {
    for (final d in drives) {
      _drives[d.subject] = d;
    }
  }

  final Store _store;
  final Map<String, DriveInfo> _drives = {};
  final _changes = StreamController<String?>.broadcast();

  @override
  String? get current => _store.drive;

  @override
  Stream<String?> watchCurrent() => _current(() => current, _changes.stream);

  @override
  Future<List<DriveInfo>> list() async => [
        for (final d in _drives.values)
          DriveInfo(
              subject: d.subject,
              name: d.name,
              emoji: d.emoji,
              unreadable: d.unreadable,
              active: d.subject == current)
      ]..sort((a, b) => a.active == b.active ? 0 : (a.active ? -1 : 1));

  @override
  Future<DriveInfo> create(String name) async {
    final subject = await _store.backend.createDrive(name);
    _drives[subject] = DriveInfo(subject: subject, name: name);
    await switchTo(subject);
    return DriveInfo(subject: subject, name: name, active: true);
  }

  @override
  Future<void> switchTo(String subject) async {
    _store.drive = subject;
    _changes.add(subject);
  }
}

/// [Identity] in memory.
class FakeIdentity implements Identity {
  FakeIdentity(this._store, {String? secret}) : _secret = secret;

  final Store _store;
  String? _secret;
  final Map<String, Profile> _profiles = {};
  final _profileChanges = StreamController<Profile>.broadcast();

  /// Secrets that [signIn] accepts, with the drive each names and whether it
  /// is on this device.
  final Map<String, ({String drive, bool needsSync})> known = {};

  /// Drive subjects the signed-in agent has work in. Signing in as a different
  /// agent brings them along once and then clears this, like the real thing.
  List<String> work = [];

  int _n = 0;

  @override
  String? get secret => _secret;

  @override
  String? get subject =>
      _secret == null ? null : 'did:ad:agent:${_secret!.hashCode}';

  @override
  Future<({String secret, String agentSubject, String drive})> create(
      String name) async {
    final drive = await _store.backend.createDrive('$name private');
    _secret = 'fake-secret-${++_n}-$name';
    _store.drive = drive;
    _profiles[_secret!] = Profile(subject: subject!, name: name);
    _profileChanges.add(_profiles[_secret!]!);
    return (secret: _secret!, agentSubject: subject!, drive: drive);
  }

  @override
  Future<SignIn> signIn(String secret) async {
    final entry = known[secret];
    if (entry == null) {
      throw const StoreException(StoreErrorKind.invalid, 'Not an agent secret');
    }
    final previous = _secret;
    final different = previous != null && previous != secret;
    final brought = different ? List<String>.of(work) : <String>[];
    if (different) work = [];
    _secret = secret;
    _store.drive = entry.drive;
    return SignIn(
        agentSubject: subject!,
        drive: entry.drive,
        needsSync: entry.needsSync,
        broughtAlong: brought,
        previousSecret: different ? previous : null);
  }

  @override
  Future<void> signOut() async => _secret = null;

  @override
  Future<Profile> profile() async {
    final secret = _secret;
    if (secret == null) {
      throw const StoreException(StoreErrorKind.invalid, 'Not signed in');
    }
    return _profiles[secret] ?? Profile(subject: subject!);
  }

  @override
  Stream<Profile> watchProfile() {
    if (_secret == null) return const Stream.empty();
    final secret = _secret!;
    return _current(() => _profiles[secret] ?? Profile(subject: subject!),
        _profileChanges.stream);
  }

  /// The profile changes without this node writing it, as when another
  /// device of the same agent edits it.
  void changeProfileElsewhere(String name) {
    final secret = _secret!;
    _profiles[secret] = Profile(subject: subject!, name: name);
    _profileChanges.add(_profiles[secret]!);
  }

  @override
  Future<void> updateProfile(
      {required String name, String description = ''}) async {
    if (name.trim().isEmpty) {
      throw const StoreException(
          StoreErrorKind.invalid, 'A profile needs a name');
    }
    _profiles[_secret!] =
        Profile(subject: subject!, name: name.trim(), description: description);
    _profileChanges.add(_profiles[_secret!]!);
  }
}

/// A node made of the fakes, to test screens that take an [AtomicParts] such
/// as `AtomicAccountButton`. Its sharing is the real rights logic with a
/// fake signer.
class FakeNode implements AtomicParts {
  FakeNode(this.store,
      {String? secret,
      Iterable<DriveInfo> drives = const [],
      InviteAcceptor? acceptInvite})
      : identity = FakeIdentity(store, secret: secret),
        drives = FakeDrives(store, drives),
        sync = FakeServerSync(),
        peers = FakePeers(),
        sharing = Sharing(store, (t, w, e, m) => 'token-$t-${w ? 'w' : 'r'}',
            acceptor: acceptInvite);

  @override
  final Store store;
  @override
  final FakeIdentity identity;
  @override
  final FakeDrives drives;
  @override
  final FakeServerSync sync;
  @override
  final FakePeers peers;
  @override
  final Sharing sharing;
}
