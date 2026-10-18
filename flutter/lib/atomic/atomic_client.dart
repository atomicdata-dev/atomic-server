import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import '../src/rust/api/assistant.dart' as assistant;
import 'session.dart';
import '../src/rust/api/simple.dart' as ffi;
import '../src/rust/api/simple/types.dart'
    show AgentInfo, CanvasListItem, VersionMetadata;

export '../src/rust/api/simple/types.dart'
    show AgentInfo, CanvasListItem, VersionMetadata;

/// An AI chat of the active drive; `lastActivity` is unix ms, 0 when empty.
typedef ChatSummary = ({String subject, String name, int lastActivity});

/// One message of a chat: the text parts of an entry, `role` user or assistant.
typedef ChatMessage = ({String id, String role, String text, int createdAt});

typedef SearchHit = ({
  String subject,
  String title,
  String className,
  double score
});

typedef DriveInfo = ({String subject, String name});

typedef RecentResource = ({
  String subject,
  String title,
  String className,
  int openedAt
});

/// Atomic Data SDK — local-first with optional sync.
///
/// Groups:
///   1. Database  — openDb()
///   2. Agent     — setup(), loadAgent(), getActiveAgent(), clearAgent()
///   3. Drive     — createDrive(), listDrives(), getActiveDrive(), setActiveDrive()
///   4. Resource  — getProperty(), setProperty()
///   5. Canvas    — createCanvas(), save/load/list/delete/rename
///   6. History   — warmResourceHistory(), getResourceHistory(), getResourceAtVersion()
///   7. Peer      — startPeer(), getPeerId(), peerAnnounce(), peerSync(), peerDiscoverSync()
///
/// Networking (group 7) is explicit. Nothing in groups 1-6 touches the network.
class AtomicClient {
  // ── 1. Database ──────────────────────────────────────────────────────────

  static Future<void> openDb(String path) => ffi.openDb(path: path);

  // ── 2. Agent ─────────────────────────────────────────────────────────────

  /// Create an agent + personal drive. Pure local.
  static Future<
          ({String agentSecret, String agentSubject, String driveSubject})>
      setup(String name) async {
    final r = await ffi.setup(name: name);
    return (
      agentSecret: r.agentSecret,
      agentSubject: r.agentSubject,
      driveSubject: r.driveSubject,
    );
  }

  /// Load an agent from a secret. Pure local.
  static Future<String> loadAgent(String secret) =>
      ffi.loadAgent(secret: secret);

  static Future<AgentInfo?> getActiveAgent() => ffi.getActiveAgent();

  static AgentInfo createAgent(String name) => ffi.createAgent(name: name);

  static AgentInfo agentFromSecret(String secret) =>
      ffi.agentFromSecret(secret: secret);

  // ── 3. Drive ─────────────────────────────────────────────────────────────

  static Future<String> createDrive(String name) => ffi.createDrive(name: name);

  static Future<List<String>> listDrives() => ffi.listDrives();

  /// The agent's drives with their names (empty when a drive has none yet).
  static Future<List<DriveInfo>> listDrivesWithNames() async => visibleDrives([
        for (final e in jsonDecode(await ffi.listDrivesWithNames()) as List)
          (
            subject: e['subject'] as String,
            name: e['name'] as String? ?? '',
          ),
      ], active: getActiveDrive());

  /// The identifier without its scheme: `did:ad:X` and `atomic:X` are one drive.
  static String driveKey(String subject) =>
      subject.replaceFirst(RegExp(r'^(did:ad:|atomic:)'), '').split('?').first;

  /// The drives worth showing: each drive once (the personal drive is listed
  /// under both spellings), and only those that are on this device with a name
  /// — a drive the personal drive lists but this device has not received has
  /// nothing to show yet. The [active] drive stays whatever its state.
  @visibleForTesting
  static List<DriveInfo> visibleDrives(List<DriveInfo> all, {String? active}) {
    final seen = <String>{};
    final out = <DriveInfo>[];
    for (final d in all) {
      final key = driveKey(d.subject);
      if (!seen.add(key)) continue;
      if (d.name.isEmpty && (active == null || driveKey(active) != key)) {
        continue;
      }
      out.add(d);
    }
    return out;
  }

  static String? getActiveDrive() => ffi.getActiveDrive();

  static Future<void> setActiveDrive(String subject) async =>
      ffi.setActiveDrive(subject: subject);

  // ── 4. Resource ──────────────────────────────────────────────────────────

  static Future<String> getProperty(String subject, String property) =>
      ffi.getProperty(subject: subject, property: property);

  static Future<void> setProperty(
          String subject, String property, String value) =>
      ffi.setProperty(subject: subject, property: property, value: value);

  // ── 4b. Assistant reads (AI chats, search, web view) ─────────────────────

  /// The person's newest AI chats, across all drives.
  static Future<List<ChatSummary>> listAiChats({int limit = 50}) async =>
      parseChats(await assistant.listAiChats(limit: limit));

  /// Remember that this device opened [subject]; local, nothing is synced.
  static void noteResourceOpened(String drive, String subject) =>
      assistant.noteResourceOpened(drive: drive, subject: subject);

  static Future<List<RecentResource>> recentResources(String drive,
          {int limit = 20}) async =>
      parseRecentResources(
          await assistant.listRecentResources(drive: drive, limit: limit));

  /// Starts an AI chat named [name] in the private drive; returns its subject.
  static Future<String> createAiChat(String name) =>
      assistant.createAiChat(name: name);

  /// Adds a text message by [role] (`user` or `assistant`) to [chat]; returns
  /// the entry's id. Signed here and synced like any other edit.
  static Future<String> appendChatEntry(
          String chat, String role, String text) =>
      assistant.appendChatEntry(
        chat: chat,
        role: role,
        partsJson: jsonEncode([
          {'type': 'text', 'text': text}
        ]),
      );

  static Future<List<ChatMessage>> readChat(String subject) async =>
      parseChatMessages(await assistant.readChat(subject: subject));

  static Future<List<SearchHit>> search(String drive, String query,
          {int limit = 20}) async =>
      parseHits(
          await assistant.search(drive: drive, query: query, limit: limit));

  /// Where the connected server's web app shows [subject]. Throws when no
  /// server is connected.
  static String resourceWebUrl(String subject) =>
      assistant.resourceWebUrl(subject: subject);

  @visibleForTesting
  static List<ChatSummary> parseChats(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            name: e['name'] as String? ?? '',
            lastActivity: (e['last_activity'] as num?)?.toInt() ?? 0,
          ),
      ];

  /// Text parts only (tool calls, reasoning and files are left out); entries
  /// without text, and roles other than user and assistant, are skipped.
  @visibleForTesting
  static List<ChatMessage> parseChatMessages(String json) {
    final out = <ChatMessage>[];
    for (final e in jsonDecode(json) as List) {
      final role = e['role'] as String? ?? '';
      if (role != 'user' && role != 'assistant') continue;
      final text = [
        for (final p in (e['parts'] as List? ?? const []))
          if (p is Map && p['type'] == 'text') p['text'] as String? ?? '',
      ].join('\n\n').trim();
      if (text.isEmpty) continue;
      out.add((
        id: e['id'] as String,
        role: role,
        text: text,
        createdAt: (e['c'] as num?)?.toInt() ?? 0,
      ));
    }
    return out;
  }

  @visibleForTesting
  static List<RecentResource> parseRecentResources(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            title: e['title'] as String? ?? '',
            className: e['class_name'] as String? ?? '',
            openedAt: (e['opened_at'] as num?)?.toInt() ?? 0,
          ),
      ];

  @visibleForTesting
  static List<SearchHit> parseHits(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            title: e['title'] as String? ?? '',
            className: e['class_name'] as String? ?? '',
            score: (e['score'] as num?)?.toDouble() ?? 0,
          ),
      ];

  // ── 5. Canvas CRUD ───────────────────────────────────────────────────────

  static Future<String> createCanvas(String name, {String? folderId}) =>
      ffi.createCanvasWithFolder(name: name, folderId: folderId);

  static Future<String> loadCanvasStrokes(String subject) =>
      ffi.loadCanvasStrokes(subject: subject);

  static Future<List<CanvasListItem>> listCanvases() => ffi.listCanvases();

  static Future<Map<String, String>> listCanvasFolderIds() async {
    final json = await ffi.listCanvasesJson();
    final list = jsonDecode(json) as List;
    return {
      for (final e in list)
        if ((e['folder_id'] as String?)?.isNotEmpty ?? false)
          e['subject'] as String: e['folder_id'] as String,
    };
  }

  static Future<void> deleteCanvas(String subject) =>
      ffi.deleteCanvas(subject: subject);

  static Future<void> renameCanvas(String subject, String name) =>
      ffi.renameCanvas(subject: subject, name: name);

  /// Rename a gallery folder (same signed commit path as [renameCanvas]).
  static Future<void> renameFolder(String subject, String name) =>
      renameCanvas(subject, name);

  // ── 6. History ───────────────────────────────────────────────────────────

  static Future<void> warmResourceHistory(String subject) =>
      ffi.warmResourceHistory(subject: subject);

  static Future<List<VersionMetadata>> getResourceHistory(String subject) =>
      ffi.getResourceHistory(subject: subject);

  static Future<String> getResourceAtVersion(
          String subject, List<int> versionId) =>
      ffi.getResourceAtVersion(
          subject: subject,
          versionId: versionId is Uint8List
              ? versionId
              : Uint8List.fromList(versionId));

  // ── 7. Peer / Sync (explicit, opt-in) ────────────────────────────────────

  /// Start the Iroh peer. Returns the NodeID. Call before any sync operations.
  static Future<String> startPeer() => ffi.startPeer();

  /// Get this device's NodeID, or null if peer not started.
  static Future<String?> getPeerId() async => ffi.getPeerId();

  /// Announce a drive on DHT so other devices can find us.
  static Future<void> peerAnnounce(String driveSubject) =>
      ffi.peerAnnounce(driveSubject: driveSubject);

  /// Sync the active drive with a peer by NodeID.
  static Future<PeerSyncResult> peerSync(String nodeId) async =>
      PeerSyncResult.fromJson(
        jsonDecode(await ffi.peerSync(nodeId: nodeId)) as Map<String, dynamic>,
      );

  /// Discover a peer via DHT and sync. Combines lookup + sync.
  static Future<int> peerDiscoverSync(String driveSubject) =>
      ffi.peerDiscoverSync(driveSubject: driveSubject);

  /// Start Iroh, sync known peers + pkarr. Use on app open and Settings → Retry.
  static Future<SyncConnectivityReport> syncConnectivityNow() async {
    final json = await ffi.syncConnectivityNow();
    final m = jsonDecode(json) as Map<String, dynamic>;
    return SyncConnectivityReport(
      imported: (m['imported'] as num?)?.toInt() ?? 0,
      livePeers: (m['live_peers'] as num?)?.toInt() ?? 0,
      message: m['message'] as String? ?? '',
      server: m['server'] as String?,
    );
  }

  /// Finds the server that hosts [drive] from the DID alone and connects to it.
  ///
  /// pkarr names candidate origins (anyone may add one), each is asked for the
  /// drive's genesis certificate, and only one whose certificate verifies
  /// against the DID is trusted. The asking is done here, with the platform's
  /// own HTTPS stack, in parallel with a short deadline each, so a dead origin
  /// cannot hold up the rest. Returns the origin, or null when none verified.
  /// What the last [discoverHomeServer] did, one line per step, for showing
  /// to the person when it did not work out.
  static final List<String> discoveryLog = [];

  static Future<String?> discoverHomeServer(
    String drive, {
    http.Client? client,
    Future<List<String>> Function(String drive)? resolve,
    bool Function(String body, String drive)? verifies,
    Future<void> Function(String origin)? connect,
    Duration timeout = const Duration(seconds: 4),
    int maxOrigins = 3,
  }) async {
    final origins =
        (await (resolve ?? _resolveOrigins)(drive)).take(maxOrigins).toList();
    if (origins.isEmpty) return null;

    final http_ = client ?? http.Client();
    final found = Completer<String?>();
    var pending = origins.length;

    Future<void> probe(String origin) async {
      var ok = false;
      try {
        final request = http.Request(
            'GET',
            Uri.parse('$origin/genesis')
                .replace(queryParameters: {'subject': drive}))
          ..followRedirects = false
          ..headers['Accept'] = 'application/ad+json';
        final response = await http.Response.fromStream(
            await http_.send(request).timeout(timeout));
        ok = response.statusCode == 200 &&
            (verifies ?? _verifies)(response.body, drive);
        if (!ok) {
          discoveryLog.add(response.statusCode == 200
              ? '$origin: its answer is not this drive\'s certificate'
              : '$origin: HTTP ${response.statusCode}');
        }
      } catch (e) {
        discoveryLog.add('$origin: ${_short(e)}');
      }
      debugPrint('[home] $origin serves the genesis: $ok');
      if (ok && !found.isCompleted) found.complete(origin);
      if (--pending == 0 && !found.isCompleted) found.complete(null);
    }

    for (final origin in origins) {
      unawaited(probe(origin));
    }
    final origin = await found.future;
    if (client == null) http_.close();
    if (origin == null) return null;
    discoveryLog.add('$origin: certificate verified, connecting');
    try {
      await (connect ?? _connect)(origin);
    } catch (e) {
      discoveryLog.add('$origin: ${_short(e)}');
      rethrow;
    }
    return origin;
  }

  static String _short(Object e) {
    final text = '$e'.replaceFirst('Exception: ', '');
    return text.length > 140 ? '${text.substring(0, 140)}…' : text;
  }

  static Future<List<String>> _resolveOrigins(String drive) =>
      ffi.resolveDriveOrigins(drive: drive);
  static bool _verifies(String body, String drive) =>
      ffi.genesisAnswerVerifies(body: body, drive: drive);
  static Future<void> _connect(String origin) =>
      ffi.connectHomeServer(origin: origin);

  // ── 8. Known peers ──────────────────────────────────────────────────────

  /// Get all known peers (persisted in DB).
  /// Returns list of {node_id: String, name: String, last_synced: String}.
  /// `last_synced` is unix millis as a string, or '' if never synced.
  static Future<List<Map<String, String>>> getKnownPeers() async {
    final json = ffi.getKnownPeersJson();
    try {
      return (jsonDecode(json) as List)
          .map((e) => {
                'node_id': (e['node_id'] ?? '') as String,
                'name': (e['name'] ?? '') as String,
                'last_synced':
                    e['last_synced'] == null ? '' : '${e['last_synced']}',
              })
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Add a peer with optional device name.
  static Future<void> addKnownPeer(String nodeId, [String name = '']) async =>
      ffi.addKnownPeer(nodeId: nodeId, name: name);

  /// Remove a peer by NodeID.
  static Future<void> removeKnownPeer(String nodeId) async =>
      ffi.removeKnownPeer(nodeId: nodeId);

  // ── 10. WebSocket sync (server-backed) ───────────────────────────────────

  /// Optional LAN hub (e.g. `http://192.168.x.x:9883`). Empty = device-to-device only.
  static const defaultServerUrl = '';

  /// Connect to Atomic Server over WebSocket; SUB active drive; apply remote updates.
  static Future<void> openWsSync(String serverUrl) =>
      ffi.openWsSync(serverUrl: serverUrl);

  static Future<void> closeWsSync() => ffi.closeWsSync();

  /// Push the active drive to `serverUrl`, so it is hosted there too.
  /// Returns the number of resources pushed.
  ///
  /// [openWsSync] fetches a drive this device lacks and pushes commits made
  /// from now on; a drive made here before any server was connected has never
  /// been offered to one. This offers it — and it is the only way a workspace
  /// made here reaches a browser, which is not a peer and cannot be paired
  /// with.
  static Future<int> syncDriveToServer(String serverUrl) =>
      ffi.syncDriveToServer(serverUrl: serverUrl);

  /// Boot / auto-login: load agent, WS sync, fetch drive, optional Iroh discover.
  /// Returns `ok` or `needs_sync`.
  static Future<String> resumeSession({
    required String serverUrl,
    required String secret,
    String? drive,
  }) async {
    final status = await ffi.resumeAppSession(
      serverUrl: serverUrl,
      secret: secret,
      driveHint: drive,
    );
    // No server in use, but known ones (paired with a code, say): the drive is
    // very likely on one of them. Looked for in the background.
    final active = getActiveDrive();
    if (status == 'ok' && serverUrl.trim().isEmpty && active != null) {
      unawaited(connectKnownServer(active).catchError((Object e) {
        debugPrint('Known server lookup failed: $e');
        return null;
      }));
    }
    return status;
  }

  /// When no server is in use, finds the known server that hosts [drive] (its
  /// genesis verifies against the DID), connects to it and makes it the one in
  /// use. Which drives of the person it also hosts is then fetched from it.
  /// Returns the server, or null.
  ///
  /// One lookup at a time: the boot path and the sign-in screen both resume the
  /// session, and a second connect would close the first one's WS session.
  static Future<String?>? _knownServerLookup;

  static Future<String?> connectKnownServer(
    String drive, {
    Future<String?> Function()? activeServer,
    Future<List<String>> Function()? knownServers,
    Future<void> Function(String origin)? setActiveServer,
    http.Client? client,
    bool Function(String body, String drive)? verifies,
    Future<void> Function(String origin)? connect,
  }) {
    final running = _knownServerLookup;
    if (running != null) return running;
    final lookup = _connectKnownServer(
      drive,
      activeServer: activeServer,
      knownServers: knownServers,
      setActiveServer: setActiveServer,
      client: client,
      verifies: verifies,
      connect: connect,
    ).whenComplete(() => _knownServerLookup = null);
    return _knownServerLookup = lookup;
  }

  static Future<String?> _connectKnownServer(
    String drive, {
    Future<String?> Function()? activeServer,
    Future<List<String>> Function()? knownServers,
    Future<void> Function(String origin)? setActiveServer,
    http.Client? client,
    bool Function(String body, String drive)? verifies,
    Future<void> Function(String origin)? connect,
  }) async {
    if (await (activeServer ?? AtomicSession.activeServer)() != null) {
      return null;
    }
    final servers = await (knownServers ?? AtomicSession.knownServers)();
    if (servers.isEmpty) return null;
    final origin = await discoverHomeServer(
      drive,
      resolve: (_) async => servers,
      client: client,
      verifies: verifies,
      connect: connect,
    );
    if (origin != null) {
      await (setActiveServer ?? AtomicSession.setActiveServer)(origin);
    }
    return origin;
  }

  static Future<void> wsSubscribeCanvas(String subject) =>
      ffi.wsSubscribeCanvas(subject: subject);

  static Future<String> createFolder(String name) =>
      ffi.createFolder(name: name);

  static Future<List<({String subject, String name})>> listFolders() async {
    final list = await ffi.listFolders();
    return list
        .map((e) => (
              subject: e.subject,
              name: e.name,
            ))
        .toList();
  }

  static Future<void> setCanvasFolder(String subject, String? folderId) =>
      ffi.setCanvasFolder(subject: subject, folderId: folderId);

  /// Block until a DB event (changed / destroyed / query membership). Null on timeout.
  static Future<Map<String, dynamic>?> pollDbEvent(
      {int timeoutMs = 60000}) async {
    final json = await ffi.pollDbEvent(timeoutMs: timeoutMs);
    if (json == null || json == 'null') return null;
    try {
      return Map<String, dynamic>.from(jsonDecode(json));
    } catch (_) {
      return null;
    }
  }

  // ── 11. Live queries ────────────────────────────────────────────────────

  /// Get persisted device name.
  static Future<String> getDeviceName() async => ffi.getDeviceName();

  /// Set device name (persisted in DB).
  static Future<void> setDeviceName(String name) async =>
      ffi.setDeviceName(name: name);

  /// Push a single stroke to a canvas (CRDT-friendly append).
  static Future<void> pushStroke(String subject, String strokeJson) =>
      ffi.pushStroke(subject: subject, strokeJson: strokeJson);

  /// Undo the last stroke edit. Persists and syncs. Returns new stroke count.
  static Future<int> undoCanvas(String subject) =>
      ffi.undoCanvas(subject: subject);

  /// Redo the last undone stroke edit. Persists and syncs. Returns new stroke count.
  static Future<int> redoCanvas(String subject) =>
      ffi.redoCanvas(subject: subject);

  static Future<bool> canUndoCanvas(String subject) =>
      ffi.canUndoCanvas(subject: subject);

  static Future<bool> canRedoCanvas(String subject) =>
      ffi.canRedoCanvas(subject: subject);

  /// Replace all strokes (used after undo/scrub). Clears and re-sets the full list.
  static Future<void> setStrokes(String subject, String strokesJson) =>
      ffi.setStrokes(subject: subject, strokesJson: strokesJson);

  /// Move canvas to a synced Loro history version and persist (history scrub).
  static Future<void> checkoutCanvasVersion(
      String subject, List<int> versionId) {
    return setStrokes(
      subject,
      jsonEncode({'checkout_version_id': versionId}),
    );
  }

  /// Get the number of currently connected live peers.
  static Future<int> livePeerCount() async => ffi.livePeerCount();

  /// Get the node IDs of currently connected live peers.
  static Set<String> livePeerIds() => ffi.livePeerIds().toSet();

  /// Fired when Iroh live-peer count changes (`connected` / `disconnected` events).
  static final ValueNotifier<int> livePeersRevision = ValueNotifier(0);

  static void notifyLivePeersChanged() {
    livePeersRevision.value++;
  }

  /// Canonical 64-char hex NodeID (matches Rust `normalize_node_id`).
  static String normalizeNodeId(String id) {
    var s = id.trim();
    for (final prefix in ['atomic:node:', 'did:ad:node:']) {
      if (s.startsWith(prefix)) {
        s = s.substring(prefix.length);
        if (s.length > 64 && s[64] == ':') {
          s = s.substring(0, 64);
        }
        break;
      }
    }
    if (s.startsWith('iroh:')) s = s.substring(5);
    return s.toLowerCase();
  }

  static bool isLivePeer(String knownNodeId, Set<String> liveIds) {
    final n = normalizeNodeId(knownNodeId);
    return liveIds.any((l) => normalizeNodeId(l) == n);
  }

  /// Block until the next sync event arrives. Reactive — no polling.
  static Future<Map<String, dynamic>?> waitForSyncEvent() async {
    final json = await ffi.waitForSyncEvent();
    if (json == 'null') return null;
    try {
      return Map<String, dynamic>.from(jsonDecode(json));
    } catch (_) {
      return null;
    }
  }

  /// Block until the live peer count changes from [current]. Reactive.
  static Future<int> waitForPeerCountChange(int current) =>
      ffi.waitForPeerCountChange(current: current);

  /// Block until a specific resource changes. Returns the subject or "timeout".
  static Future<String> watchResource(String subject) =>
      ffi.watchResource(subject: subject);

  /// Block until a child of [parent] changes. Returns the changed subject.
  /// Times out after 60s and returns "timeout".
  static Future<String> watchChildren(String parent) =>
      ffi.watchChildren(parent: parent);

  // ── 9. Sync events ─────────────────────────────────────────────────────

  /// Poll for incoming sync events (peer connected and synced).
  /// Returns a list of {remoteNodeId, resourcesImported, timestamp}.
  static Future<List<Map<String, dynamic>>> pollSyncEvents() async {
    final json = await ffi.pollSyncEvents();
    try {
      return List<Map<String, dynamic>>.from(
        (jsonDecode(json) as List).map((e) => Map<String, dynamic>.from(e)),
      );
    } catch (_) {
      return [];
    }
  }
}

/// Result of [`AtomicClient.syncConnectivityNow`].
class SyncConnectivityReport {
  final int imported;
  final int livePeers;
  final String message;

  /// The server the drive was found on through pkarr, when it was.
  final String? server;

  const SyncConnectivityReport({
    required this.imported,
    required this.livePeers,
    required this.message,
    this.server,
  });
}

/// What a sync did, in both directions.
///
/// A count of imports alone says "0" for the two things that most often
/// happen — sending a workspace somewhere that has none, and both sides
/// already holding the same thing — and "0" reads as failure.
class PeerSyncResult {
  const PeerSyncResult({
    required this.imported,
    required this.pushed,
    required this.inSync,
    this.peerName,
  });

  /// Resources taken from the other device.
  final int imported;

  /// Resources handed to it.
  final int pushed;

  /// Both sides already held the same thing. Nothing moved, nothing needed to.
  final bool inSync;

  /// What the other device calls itself, if it said.
  final String? peerName;

  factory PeerSyncResult.fromJson(Map<String, dynamic> json) => PeerSyncResult(
        imported: (json['imported'] as num?)?.toInt() ?? 0,
        pushed: (json['pushed'] as num?)?.toInt() ?? 0,
        inSync: json['in_sync'] == true,
        peerName: json['peer_name'] as String?,
      );

  /// What happened, as a person would say it.
  String describe([String? fallbackName]) {
    final name = peerName?.isNotEmpty == true ? peerName : fallbackName;
    final withWhom = name == null ? '' : ' with $name';

    if (imported > 0 && pushed > 0) {
      return 'Synced$withWhom — sent $pushed, received $imported';
    }

    if (pushed > 0) {
      return 'Sent $pushed ${pushed == 1 ? 'resource' : 'resources'}$withWhom';
    }

    if (imported > 0) {
      return 'Received $imported ${imported == 1 ? 'resource' : 'resources'}$withWhom';
    }

    if (inSync) {
      return 'Already in sync$withWhom';
    }

    return 'Nothing to sync$withWhom';
  }
}
