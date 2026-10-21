import 'dart:async';
import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart'
    show
        ActivityEntry,
        AssistantJson,
        ChatEntry,
        ChatMessage,
        ChatPage,
        ChatPart,
        ChatRoomMessage,
        ChatSummary,
        ConversationMessage,
        ConversationRow,
        DriveInfo,
        NotificationItem,
        RecentResource,
        SearchHit;
import 'package:atomic_chat/atomic_chat.dart' as chat show driveKey;
import 'package:flutter/foundation.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart'
    show PlatformInt64Util;
import 'package:http/http.dart' as http;
import '../src/rust/api/assistant.dart' as assistant;
import '../src/rust/api/context.dart' as context;
import '../src/rust/api/embed.dart' as embed;
import 'session.dart';
import '../screens/store_recovery_screen.dart' show StoreRecoveryNotice;
import '../src/rust/api/simple.dart' as ffi;
import '../src/rust/api/simple/types.dart' show AgentInfo, VersionMetadata;

export '../src/rust/api/simple/types.dart' show AgentInfo, VersionMetadata;

/// Atomic Data SDK — local-first with optional sync.
///
/// Groups:
///   1. Database  — openDb()
///   2. Agent     — setup(), loadAgent(), getActiveAgent(), clearAgent()
///   3. Drive     — createDrive(), listDrives(), getActiveDrive(), setActiveDrive()
///   4. Resource  — getProperty(), setProperty()
///   6. History   — warmResourceHistory(), getResourceHistory()
///   7. Peer      — startPeer(), getPeerId(), peerAnnounce(), peerSync(), peerDiscoverSync()
///
/// Networking (group 7) is explicit. Nothing in groups 1-6 touches the network.
class AtomicClient {
  // ── 1. Database ──────────────────────────────────────────────────────────

  static Future<void> openDb(String path) => ffi.openDb(path: path);

  /// Set when `openDb` found the store damaged and set it aside.
  static StoreRecoveryNotice? storeRecovery() {
    final r = ffi.storeRecovery();
    if (r == null) return null;
    return StoreRecoveryNotice(
        keptPath: r.keptPath, reason: r.reason, repaired: r.repaired);
  }

  /// Make every write so far durable (the app is going to the background).
  static Future<void> flushDb() => ffi.flushDb();

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

  /// The active agent's profile as JSON `{subject, name, description, emoji?,
  /// imageUrl?, iconFile?}`.
  static Future<String> getOwnProfile() => ffi.getOwnProfile();

  /// The bytes of a File resource (a profile picture) this device holds, else
  /// null (the File or its bytes have not arrived).
  static Future<Uint8List?> readFileBytes(String file) =>
      ffi.readFileBytes(file: file);

  /// The bytes of a File resource: from this device, else downloaded from the
  /// connected server (signed, checked against the blob's hash, an image of at
  /// most 16 MB) and kept. Throws with the reason (HTTP status included).
  static Future<Uint8List> fetchFileBytes(String file) =>
      ffi.fetchFileBytes(file: file);

  /// Save the active agent's name and description (a commit by the agent).
  /// [icon] is the subject of the picture's File (empty removes the picture,
  /// null leaves it).
  static Future<void> setAgentProfile(String name, String description,
          {String? icon}) =>
      ffi.setAgentProfile(name: name, description: description, icon: icon);

  /// Keeps a picked picture as a File in the active workspace; returns the
  /// File's subject (for [setAgentProfile]'s `icon`).
  static Future<String> uploadAgentPicture(
          String filename, String mimetype, Uint8List bytes) =>
      ffi.uploadAgentPicture(
          filename: filename, mimetype: mimetype, bytes: bytes);

  static AgentInfo createAgent(String name) => ffi.createAgent(name: name);

  static AgentInfo agentFromSecret(String secret) =>
      ffi.agentFromSecret(secret: secret);

  /// What this build and platform are: `{version, os, arch}`.
  static Map<String, dynamic> deviceInfoJson() {
    try {
      return jsonDecode(ffi.deviceInfo()) as Map<String, dynamic>;
    } catch (_) {
      return const {};
    }
  }

  /// How much of the person's data this device holds: the bridge's
  /// `store_stats` JSON (`resources`, `loro_bytes`, `blob_bytes`,
  /// `disk_bytes?`, `drives`). Counted on the Rust async pool.
  static Future<Map<String, dynamic>> storeStatsJson() async =>
      jsonDecode(await ffi.storeStats()) as Map<String, dynamic>;

  // ── 3. Drive ─────────────────────────────────────────────────────────────

  static Future<String> createDrive(String name) => ffi.createDrive(name: name);

  static Future<List<String>> listDrives() => ffi.listDrives();

  /// The agent's drives with their names (empty when a drive has none yet),
  /// as [visibleDrives] keeps them.
  static Future<List<DriveInfo>> listDrivesWithNames() async =>
      AssistantJson.parseDrives(await ffi.listDrivesWithNames(),
          active: getActiveDrive());

  /// The identifier without its scheme: `did:ad:X` and `atomic:X` are one drive.
  static String driveKey(String subject) => chat.driveKey(subject);

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
  // The JSON of `atomic_lib::host` is read by `AssistantJson` (atomic_chat).

  /// The person's newest AI chats, across all drives. [offset] skips that many newer chats, to page through all of them.
  static Future<List<ChatSummary>> listAiChats(
          {int limit = 50, int offset = 0}) async =>
      AssistantJson.parseChats(
          await assistant.listAiChats(limit: limit, offset: offset));

  /// Remember that this device opened [subject]; local, nothing is synced.
  static void noteResourceOpened(String drive, String subject) =>
      assistant.noteResourceOpened(drive: drive, subject: subject);

  static Future<List<RecentResource>> recentResources(String drive,
          {int limit = 20}) async =>
      AssistantJson.parseRecentResources(
          await assistant.listRecentResources(drive: drive, limit: limit));

  /// The person's favorites (all drives), newest added first. `openedAt` is 0.
  static Future<List<RecentResource>> favorites({int limit = 100}) async =>
      AssistantJson.parseRecentResources(
          await assistant.listFavorites(limit: limit));

  /// The notifications of the Inbox in the private drive, newest first.
  static Future<List<NotificationItem>> notifications({int limit = 50}) async =>
      AssistantJson.parseNotifications(
          await assistant.listNotifications(limit: limit));

  /// Marks a notification read (and its copies), synced like any other edit.
  static Future<void> markNotificationRead(String subject) =>
      assistant.markNotificationRead(subject: subject);

  /// The person's conversations (DMs and group chats), titled by who is in
  /// them, newest message first.
  static Future<List<ConversationRow>> conversations({int limit = 100}) async =>
      AssistantJson.parseConversations(
          await assistant.listConversations(limit: limit));

  /// The messages of a conversation, oldest first, read from the local store.
  static Future<List<ConversationMessage>> readConversation(
          String subject) async =>
      AssistantJson.parseConversationMessages(
          await assistant.readConversation(subject: subject));

  /// Sends [text] in a conversation as this device's agent (sealed, signed,
  /// synced like any edit); returns the message's subject.
  static Future<String> sendConversationMessage(String subject, String text) =>
      assistant.sendConversationMessage(subject: subject, text: text);

  /// The chat of a meeting or chat room, oldest first, from the local store.
  static Future<List<ChatRoomMessage>> readChatRoom(String subject) async =>
      AssistantJson.parseChatRoomMessages(
          await assistant.readChatRoom(subject: subject));

  /// Sends [text] in a meeting or chat room as this device's agent.
  static Future<String> sendChatRoomMessage(String subject, String text) =>
      assistant.sendChatRoomMessage(subject: subject, text: text);

  /// Gets a conversation onto this device and follows its new messages over
  /// the open sync session. Best effort: throws when there is no session.
  static Future<void> followConversation(String subject) =>
      assistant.followConversation(subject: subject);

  /// The emojis (`{subject: emoji}`) of those of [subjects] that have one.
  static Future<Map<String, String>> resourceIcons(
          List<String> subjects) async =>
      AssistantJson.parseIcons(
          await assistant.resourceIcons(subjects: subjects));

  /// What changed lately in every drive, newest first, by whom.
  static Future<List<ActivityEntry>> activity(
          {int limit = 100, bool includeOwn = false}) async =>
      [
        for (final a in await assistant.listActivity(
            limit: limit, includeOwn: includeOwn))
          _activityEntry(a),
      ];

  static ActivityEntry _activityEntry(assistant.ActivityEntry a) =>
      ActivityEntry.withPictures(
        subject: a.subject,
        drive: a.drive,
        kind: a.kind,
        at: a.at.toInt(),
        actor: a.actor,
        name: a.name,
        className: a.className,
        pictures: a.pictures,
      );

  /// One page of the full Activity feed, newest first: the entries after
  /// [before] (null for the first page).
  static Future<List<ActivityEntry>> activityPage(
          {ActivityEntry? before,
          int limit = 50,
          bool includeOwn = false}) async =>
      [
        for (final a in await assistant.listActivityPage(
            beforeAt: before == null ? null : PlatformInt64Util.from(before.at),
            beforeSubject: before?.subject,
            limit: limit,
            includeOwn: includeOwn))
          _activityEntry(a),
      ];

  /// Starts an AI chat named [name] in the private drive; returns its subject.
  static Future<String> createAiChat(String name) =>
      assistant.createAiChat(name: name);

  /// Imports a whole AI chat in one go: [entriesJson] is a JSON array of
  /// `{role, parts, c}`, oldest first. Returns the chat's subject.
  static Future<String> importAiChat(String name, String entriesJson) =>
      assistant.importAiChat(name: name, entriesJson: entriesJson);

  /// Creates a resource of [classUrl] named [name] ("Untitled" when empty)
  /// in [drive], signed here and synced like any other edit; returns its
  /// subject.
  static Future<String> createResourceOfClass(
          String drive, String classUrl, String name) =>
      assistant.createResourceOfClass(
          drive: drive, classUrl: classUrl, name: name);

  /// Adds a text message by [role] (`user` or `assistant`) to [chat]; returns
  /// the entry's id. Signed here and synced like any other edit.
  static Future<String> appendChatEntry(
          String chat, String role, String text) =>
      assistant.appendChatEntry(
        chat: chat,
        role: role,
        partsJson: AssistantJson.textParts(text),
      );

  /// Adds a message by [role] with all its [parts] (text, files, tool calls,
  /// in the web app's format) to [chat]; returns the entry's id.
  static Future<String> appendChatEntryParts(
          String chat, String role, List<ChatPart> parts) =>
      assistant.appendChatEntry(
        chat: chat,
        role: role,
        partsJson: jsonEncode([for (final p in parts) p.toJson()]),
      );

  /// Readable text of [subject] from the local store (title, class,
  /// properties, children, document text), at most [maxChars] long.
  static Future<String> resourceText(String subject, {int maxChars = 4000}) =>
      context.readResourceText(subject: subject, maxChars: maxChars);

  static Future<List<ChatMessage>> readChat(String subject) async =>
      AssistantJson.parseChatMessages(
          await assistant.readChat(subject: subject));

  /// A window of an AI chat: the newest [limit] messages before [before]
  /// (null: the newest of all), with cursors for the windows around it.
  static Future<ChatPage<ChatEntry>> readChatEntriesPage(String subject,
          {String? before, int limit = 50}) async =>
      AssistantJson.parsePage(
          await assistant.readChatPage(
              subject: subject, before: before, limit: limit),
          'entries',
          AssistantJson.parseChatEntries);

  /// The messages of an AI chat after the cursor [after].
  static Future<ChatPage<ChatEntry>> readChatEntriesAfter(
          String subject, String after, {int limit = 100}) async =>
      AssistantJson.parsePage(
          await assistant.readChatAfter(
              subject: subject, after: after, limit: limit),
          'entries',
          AssistantJson.parseChatEntries);

  /// A window of a meeting or chat room (see [readChatEntriesPage]).
  static Future<ChatPage<ChatRoomMessage>> readChatRoomPage(String subject,
          {String? before, int limit = 50}) async =>
      AssistantJson.parsePage(
          await assistant.readChatRoomPage(
              subject: subject, before: before, limit: limit),
          'messages',
          AssistantJson.parseChatRoomMessages);

  /// The lines of a meeting or chat room after the cursor [after].
  static Future<ChatPage<ChatRoomMessage>> readChatRoomAfter(
          String subject, String after, {int limit = 100}) async =>
      AssistantJson.parsePage(
          await assistant.readChatRoomAfter(
              subject: subject, after: after, limit: limit),
          'messages',
          AssistantJson.parseChatRoomMessages);

  /// A window of a conversation; only its messages are decrypted.
  static Future<ChatPage<ConversationMessage>> readConversationPage(
          String subject,
          {String? before,
          int limit = 50}) async =>
      AssistantJson.parsePage(
          await assistant.readConversationPage(
              subject: subject, before: before, limit: limit),
          'messages',
          AssistantJson.parseConversationMessages);

  /// The messages of a conversation after the cursor [after].
  static Future<ChatPage<ConversationMessage>> readConversationAfter(
          String subject, String after, {int limit = 100}) async =>
      AssistantJson.parsePage(
          await assistant.readConversationAfter(
              subject: subject, after: after, limit: limit),
          'messages',
          AssistantJson.parseConversationMessages);

  /// Every message of an AI chat with all its parts, oldest first.
  static Future<List<ChatEntry>> readChatEntries(String subject) async =>
      AssistantJson.parseChatEntries(
          await assistant.readChat(subject: subject));

  /// Searches every drive; only in [drive] when it is given. With [classes]
  /// (`drive`, `aichat`, `conversation`, `chatroom`) only resources of those
  /// classes, chosen before the [limit] cuts the list.
  static Future<List<SearchHit>> search(String query,
          {String? drive,
          int limit = 20,
          List<String> classes = const []}) async =>
      AssistantJson.parseHits(await assistant.search(
          drive: drive, query: query, limit: limit, classes: classes));

  /// Reads the search index once so the first keystroke is not cold.
  static Future<void> warmSearch() => assistant.warmSearch();

  /// Where the connected server's web app shows [subject]. Throws when no
  /// server is connected.
  static String resourceWebUrl(String subject) =>
      assistant.resourceWebUrl(subject: subject);

  // ── 6. History ───────────────────────────────────────────────────────────

  static Future<void> warmResourceHistory(String subject) =>
      ffi.warmResourceHistory(subject: subject);

  static Future<List<VersionMetadata>> getResourceHistory(String subject) =>
      ffi.getResourceHistory(subject: subject);

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

  /// What the search for this account's other devices is doing: the bridge's
  /// `peer_search_status` JSON (state, message, detail, retry_in_secs).
  static Map<String, dynamic> peerSearchStatus() {
    try {
      return jsonDecode(ffi.peerSearchStatus()) as Map<String, dynamic>;
    } catch (_) {
      return const {};
    }
  }

  /// Look for the other devices now: a Search again button, a network change.
  static void peerSearchAgain() {
    try {
      ffi.peerSearchAgain();
    } catch (e) {
      debugPrint('peerSearchAgain: $e');
    }
  }

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

  /// Every https origin [drive]'s pkarr record names whose `/genesis`
  /// answer verifies against the DID: the servers that host it, found without
  /// being typed in. Same checks as [discoverHomeServer], all of them kept.
  static Future<List<String>> verifiedDriveOrigins(
    String drive, {
    http.Client? client,
    Future<List<String>> Function(String drive)? resolve,
    bool Function(String body, String drive)? verifies,
    Duration timeout = const Duration(seconds: 4),
    int maxOrigins = 6,
  }) async {
    final origins =
        (await (resolve ?? _resolveOrigins)(drive)).take(maxOrigins).toList();
    if (origins.isEmpty) return const [];
    final http_ = client ?? http.Client();
    try {
      final ok = await Future.wait(origins.map((origin) async {
        try {
          final request = http.Request(
              'GET',
              Uri.parse('$origin/genesis')
                  .replace(queryParameters: {'subject': drive}))
            ..followRedirects = false
            ..headers['Accept'] = 'application/ad+json';
          final response = await http.Response.fromStream(
              await http_.send(request).timeout(timeout));
          return response.statusCode == 200 &&
              (verifies ?? _verifies)(response.body, drive);
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

  /// One call from the embedded renderer's page to the store: a method and its
  /// arguments as JSON, answered as JSON (see `planning/flutter-resource-webview.md`).
  static Future<String> embedCall(String method, String argsJson) =>
      embed.embedCall(method: method, argsJson: argsJson);

  // ── 8. Known peers ──────────────────────────────────────────────────────

  /// Devices connected now that are not paired: [{node_id, name}]. Display
  /// only; the name is what they said in HELLO, '' if nothing.
  static Future<List<Map<String, String>>> liveUnsavedPeers() async {
    try {
      return (jsonDecode(ffi.liveUnsavedPeersJson()) as List)
          .map((e) => {
                'node_id': (e['node_id'] ?? '') as String,
                'name': (e['name'] ?? '') as String,
              })
          .toList();
    } catch (_) {
      return [];
    }
  }

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
                'relay_url': (e['relay_url'] ?? '') as String,
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

  /// Get the number of currently connected live peers.
  static Future<int> livePeerCount() async => ffi.livePeerCount();

  /// Get the node IDs of currently connected live peers.
  static Set<String> livePeerIds() => ffi.livePeerIds().toSet();

  /// Fired when Iroh live-peer count changes (`connected` / `disconnected` events).
  static final ValueNotifier<int> livePeersRevision = ValueNotifier(0);

  /// Bumped when data may have arrived from elsewhere (a background sync
  /// finished): lists and open conversations read the store again.
  static final ValueNotifier<int> storeRevision = ValueNotifier(0);

  static void notifyStoreChanged() {
    storeRevision.value++;
  }

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
