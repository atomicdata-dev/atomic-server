import 'dart:async';

import 'package:atomic_store/atomic_store.dart';
import 'package:http/http.dart' as http;

import '../bridge/api/error.dart' as bridge;
import '../bridge/api/resources.dart' as bridge;
import '../bridge/api/simple/sync.dart' as free;
import 'bridge_store_backend.dart' show storeExceptionFromBridge;

/// Whether the node is connected to an Atomic Server.
class SyncStatus {
  const SyncStatus({this.connected = false, this.origin});

  /// A session is open: local writes go out, the server's changes come in.
  final bool connected;

  /// The server of the last [ServerSync.connect], also after it dropped.
  final String? origin;

  @override
  bool operator ==(Object other) =>
      other is SyncStatus &&
      other.connected == connected &&
      other.origin == origin;

  @override
  int get hashCode => Object.hash(connected, origin);

  @override
  String toString() => 'SyncStatus(connected: $connected, origin: $origin)';
}

/// How a start-up connect to the home server ended.
enum ResumeStatus {
  /// Connected, and the node's drive is on this device.
  ready,

  /// The server did not answer in time or refused: working offline; writes
  /// wait on disk for the next [ServerSync.connect].
  offline,

  /// Connected (or no server given) but the node's drive is not on this
  /// device: pair with a device that has it, or find a server that hosts it.
  needsSync,
}

/// Sync with an Atomic Server over WebSocket. The node signs in with its
/// agent (no password), subscribes to its drive, applies the server's changes
/// to the local store and sends every write that waits. Writes always succeed
/// locally first.
///
/// This is the app-start path of the atomic.place app, as a package API:
///
/// ```dart
/// final status = await node.sync.resume(savedServerOrigin);
/// if (status == ResumeStatus.needsSync) { /* pair, or discover */ }
/// node.sync.watchStatus().listen((s) => print(s.connected));
/// ```
abstract interface class ServerSync {
  /// The session now.
  SyncStatus get status;

  /// [status] now and after every change, as seen by polling once a second.
  Stream<SyncStatus> watchStatus();

  /// Opens the session at [origin] (for example `https://example.com`, no
  /// path), replacing the one that is open. Throws a `StoreException` when
  /// the server cannot be reached or refuses the agent.
  Future<void> connect(String origin);

  /// Stops the session. Writes wait on disk for the next [connect].
  Future<void> disconnect();

  /// Connect on app start: opens the session at [origin] (when not null),
  /// waiting at most [timeout] (a server that does not answer must not hold
  /// up a cold start), and says whether the node's drive is on this device.
  /// Never throws for an unreachable server: that is [ResumeStatus.offline].
  Future<ResumeStatus> resume(String? origin,
      {Duration timeout = const Duration(seconds: 10)});

  /// Sends the writes that wait now. `true` when nothing is left; without a
  /// session nothing is sent.
  Future<bool> pushPending();

  /// The servers that host [drive] and prove it: the https origins its public
  /// directory record (pkarr) names whose `/genesis` answer verifies against
  /// the drive's DID. Nothing from the record is trusted unverified.
  Future<List<String>> verifiedOrigins(String drive);

  /// Finds the first server that hosts [drive] and proves it (see
  /// [verifiedOrigins]) and [connect]s to it. Returns its origin, or `null`
  /// when none verified. [log] says what was tried, for showing to the person
  /// when it did not work out.
  Future<String?> discover(String drive);

  /// What the last [discover] did, one line per step.
  List<String> get log;
}

/// [ServerSync] over one node's handle.
class BridgeServerSync implements ServerSync {
  BridgeServerSync(this._handle, this._store, {http.Client? client})
      : _discovery = HomeServerDiscovery(
          resolve: (drive) => free.resolveDriveOrigins(drive: drive),
          verifies: (body, drive) =>
              free.genesisAnswerVerifies(body: body, drive: drive),
          client: client,
        );

  final bridge.AtomicStore _handle;
  final Store _store;
  final HomeServerDiscovery _discovery;

  @override
  SyncStatus get status => SyncStatus(
      connected: _handle.isSyncing(), origin: _handle.connectedServer());

  @override
  Stream<SyncStatus> watchStatus() {
    Timer? timer;
    SyncStatus? last;
    late final StreamController<SyncStatus> controller;
    void tick() {
      final now = status;
      if (now != last) controller.add(last = now);
    }

    controller = StreamController<SyncStatus>(
      onListen: () {
        tick();
        timer = Timer.periodic(const Duration(seconds: 1), (_) => tick());
      },
      onCancel: () => timer?.cancel(),
    );
    return controller.stream;
  }

  @override
  Future<void> connect(String origin) async {
    try {
      await _handle.openWsSync(serverOrigin: origin);
    } on bridge.AtomicError catch (e) {
      throw storeExceptionFromBridge(e);
    }
  }

  @override
  Future<void> disconnect() => _handle.closeWsSync();

  @override
  Future<ResumeStatus> resume(String? origin,
      {Duration timeout = const Duration(seconds: 10)}) async {
    final trimmed = origin?.trim() ?? '';
    var reached = true;
    if (trimmed.isNotEmpty) {
      try {
        await connect(trimmed).timeout(timeout);
      } on TimeoutException {
        reached = false;
      } on StoreException {
        reached = false;
      }
    }
    final drive = _store.drive;
    if (drive != null && await _store.getResourceOrNull(drive) != null) {
      return ResumeStatus.ready;
    }
    return reached ? ResumeStatus.needsSync : ResumeStatus.offline;
  }

  @override
  Future<bool> pushPending() => _handle.pushPending();

  @override
  Future<List<String>> verifiedOrigins(String drive) =>
      _discovery.verifiedOrigins(drive);

  @override
  Future<String?> discover(String drive) =>
      _discovery.discover(drive, connect: connect);

  @override
  List<String> get log => _discovery.log;
}

/// Finding the server that hosts a drive, without being told where it is.
///
/// The drive's public directory record (pkarr) names origins. Anyone may add
/// to it, so each origin is asked for `GET /genesis?subject=<drive>` and only
/// one whose answer verifies against the drive's DID is trusted. The asking
/// is done with Dart's `http` (the platform's own HTTPS stack, which trusts
/// the device's certificates), in parallel with a short deadline each so a
/// dead origin cannot hold up the rest. The record lookup and the
/// verification are injected so tests need neither network nor native code.
class HomeServerDiscovery {
  HomeServerDiscovery({
    required this.resolve,
    required this.verifies,
    this.client,
    this.timeout = const Duration(seconds: 4),
  });

  /// The origins the record of a drive names.
  final Future<List<String>> Function(String drive) resolve;

  /// Whether a `/genesis` answer is the drive's own certificate.
  final bool Function(String body, String drive) verifies;

  final http.Client? client;
  final Duration timeout;

  final List<String> _log = [];

  /// What the last [discover] did, one line per step.
  List<String> get log => List.unmodifiable(_log);

  /// The first verified origin, [connect]ed; `null` when none verified.
  /// Rethrows what [connect] throws (after logging it).
  Future<String?> discover(
    String drive, {
    required Future<void> Function(String origin) connect,
    int maxOrigins = 3,
  }) async {
    _log.clear();
    final origins = (await resolve(drive)).take(maxOrigins).toList();
    if (origins.isEmpty) return null;

    final http_ = client ?? http.Client();
    final found = Completer<String?>();
    var pending = origins.length;

    Future<void> probe(String origin) async {
      var ok = false;
      try {
        final response = await _get(http_, origin, drive, retry: true);
        ok = response.statusCode == 200 && verifies(response.body, drive);
        if (!ok) {
          _log.add(response.statusCode == 200
              ? "$origin: its answer is not this drive's certificate"
              : '$origin: HTTP ${response.statusCode}');
        }
      } catch (e) {
        _log.add('$origin: ${_short(e)}');
      }
      if (ok && !found.isCompleted) found.complete(origin);
      if (--pending == 0 && !found.isCompleted) found.complete(null);
    }

    for (final origin in origins) {
      unawaited(probe(origin));
    }
    final origin = await found.future;
    if (client == null) http_.close();
    if (origin == null) return null;
    _log.add('$origin: certificate verified, connecting');
    try {
      await connect(origin);
    } catch (e) {
      _log.add('$origin: ${_short(e)}');
      rethrow;
    }
    return origin;
  }

  /// Every origin of the record whose `/genesis` verifies, none connected.
  Future<List<String>> verifiedOrigins(String drive,
      {int maxOrigins = 6}) async {
    final origins = (await resolve(drive)).take(maxOrigins).toList();
    if (origins.isEmpty) return const [];
    final http_ = client ?? http.Client();
    try {
      final ok = await Future.wait(origins.map((origin) async {
        try {
          final response = await _get(http_, origin, drive);
          return response.statusCode == 200 && verifies(response.body, drive);
        } catch (_) {
          return false;
        }
      }));
      return [
        for (var i = 0; i < origins.length; i++)
          if (ok[i]) origins[i]
      ];
    } finally {
      if (client == null) http_.close();
    }
  }

  http.Request _request(String origin, String drive) => http.Request('GET',
      Uri.parse('$origin/genesis').replace(queryParameters: {'subject': drive}))
    ..followRedirects = false
    ..headers['Accept'] = 'application/ad+json';

  /// One quick retry when the connection is closed before a response: a
  /// pooled keep-alive connection the server already dropped fails this way
  /// and works again on a fresh one.
  Future<http.Response> _get(http.Client c, String origin, String drive,
      {bool retry = false}) async {
    Future<http.Response> once() async => http.Response.fromStream(
        await c.send(_request(origin, drive)).timeout(timeout));
    try {
      return await once();
    } on http.ClientException {
      if (!retry) rethrow;
      return once();
    }
  }

  static String _short(Object e) {
    final text = '$e'.replaceFirst('Exception: ', '');
    return text.length > 140 ? '${text.substring(0, 140)}…' : text;
  }
}
