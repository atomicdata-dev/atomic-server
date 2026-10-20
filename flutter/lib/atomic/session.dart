import 'package:atomic_flutter/atomic_flutter.dart'
    show normalizeServerUrl, sameOrigin;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Persists the atomic session across restarts.
///
/// The **agent secret** is the one sensitive value — it is the account's private
/// key — so it lives in platform secure storage (EncryptedSharedPreferences on
/// Android, Keychain on iOS), not in plain SharedPreferences. Everything else
/// (server URL, active drive, known servers, peers) is non-sensitive routing
/// state and stays in SharedPreferences.
class AtomicSession {
  static const _keyServerUrl = 'atomic_server_url';
  static const _keySecret = 'atomic_agent_secret';
  static const _keyDrive = 'atomic_drive';

  static const _secure = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static Future<void> save({
    required String serverUrl,
    required String secret,
    String? drive,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyServerUrl, serverUrl);
    await _secure.write(key: _keySecret, value: secret);
    // Clear any legacy plaintext copy left in SharedPreferences.
    await prefs.remove(_keySecret);
    if (isResumableDrive(drive)) {
      await prefs.setString(_keyDrive, drive!);
    }

    await addKnownServer(serverUrl);
  }

  /// Only a drive that can be found again from its own subject is worth
  /// remembering: an old `https://…/drive/…` one cannot (nothing resolves it
  /// from a cold start), and resuming with it as the hint left the person at
  /// the sign-in screen with a perfectly good secret.
  static bool isResumableDrive(String? drive) =>
      drive != null &&
      (drive.startsWith('did:ad:') || drive.startsWith('atomic:'));

  static Future<void> saveDrive(String drive) async {
    if (!isResumableDrive(drive)) return;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyDrive, drive);
  }

  static Future<({String serverUrl, String secret, String? drive})?>? _early;

  /// Starts [load] from `main`, once: the sign-in screen takes the result
  /// with [loadEarly] instead of reading again.
  static void preload() => _early ??= load();

  /// The [preload]ed session the first time (once), else a fresh [load].
  static Future<({String serverUrl, String secret, String? drive})?>
      loadEarly() {
    final early = _early;
    _early = null;
    return early ?? load();
  }

  static Future<({String serverUrl, String secret, String? drive})?>
      load() async {
    final prefs = await SharedPreferences.getInstance();
    final serverUrl = prefs.getString(_keyServerUrl);
    final secret = await _loadSecret(prefs);
    if (serverUrl == null || secret == null) return null;
    return (
      serverUrl: serverUrl,
      secret: secret,
      drive: isResumableDrive(prefs.getString(_keyDrive))
          ? prefs.getString(_keyDrive)
          : null,
    );
  }

  /// Read the secret from secure storage, migrating a pre-existing plaintext
  /// SharedPreferences secret into it on first run so nobody has to re-sign-in.
  static Future<String?> _loadSecret(SharedPreferences prefs) async {
    final secure = await _secure.read(key: _keySecret);
    if (secure != null) return secure;

    final legacy = prefs.getString(_keySecret);
    if (legacy != null) {
      await _secure.write(key: _keySecret, value: legacy);
      await prefs.remove(_keySecret);
      return legacy;
    }
    return null;
  }

  static Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_keyServerUrl);
    await _secure.delete(key: _keySecret);
    await prefs.remove(_keySecret); // legacy, if any
    await prefs.remove(_keyDrive);
  }

  // ── Servers ───────────────────────────────────────────────────────
  //
  // The session has one *active* server, but remembers the others, so
  // switching back is a tap rather than retyping a URL. Sync hubs are
  // optional here: an empty list is a device-to-device-only setup.

  static const _keyKnownServers = 'atomic_known_servers';

  /// Every server this device knows, active one included. Stable order —
  /// switching must not shuffle the list under the finger that tapped it.
  static Future<List<String>> knownServers() async {
    final prefs = await SharedPreferences.getInstance();

    return prefs.getStringList(_keyKnownServers) ?? [];
  }

  /// The server in use, or null when syncing device-to-device only.
  static Future<String?> activeServer() async {
    final prefs = await SharedPreferences.getInstance();
    final url = prefs.getString(_keyServerUrl);

    return url == null || url.isEmpty ? null : url;
  }

  /// Remembers `url` without switching to it. Normalizes first, so
  /// `localhost:9883` and `http://localhost:9883/` are one entry.
  static Future<void> addKnownServer(String url) async {
    final normalized = normalizeServerUrl(url);

    if (normalized.isEmpty) return;

    final prefs = await SharedPreferences.getInstance();
    final servers = prefs.getStringList(_keyKnownServers) ?? [];

    if (servers.any((s) => sameOrigin(s, normalized))) return;

    servers.add(normalized);
    await prefs.setStringList(_keyKnownServers, servers);
  }

  /// Makes `url` the active server, remembering it.
  static Future<void> setActiveServer(String url) async {
    final normalized = normalizeServerUrl(url);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyServerUrl, normalized);
    await addKnownServer(normalized);
  }

  /// Forgets `url`. Clears the active server too when it was the one removed,
  /// leaving the device syncing peer-to-peer rather than pointed at a server
  /// it was just told to forget.
  static Future<void> removeKnownServer(String url) async {
    // Normalized first: `localhost:9883` parses as scheme `localhost`, which
    // matches nothing stored. Removing must accept what adding accepted.
    final normalized = normalizeServerUrl(url);
    final prefs = await SharedPreferences.getInstance();
    final servers = prefs.getStringList(_keyKnownServers) ?? [];
    servers.removeWhere((s) => sameOrigin(s, normalized));
    await prefs.setStringList(_keyKnownServers, servers);

    if (sameOrigin(normalized, prefs.getString(_keyServerUrl))) {
      await prefs.setString(_keyServerUrl, '');
    }
  }

  // ── Paired peers ──────────────────────────────────────────────────

  static const _keyPeers = 'atomic_peers';

  static Future<List<String>> loadPeers() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList(_keyPeers) ?? [];
  }

  static Future<void> addPeer(String nodeId) async {
    final prefs = await SharedPreferences.getInstance();
    final peers = prefs.getStringList(_keyPeers) ?? [];
    if (!peers.contains(nodeId)) {
      peers.add(nodeId);
      await prefs.setStringList(_keyPeers, peers);
    }
  }

  static Future<void> removePeer(String nodeId) async {
    final prefs = await SharedPreferences.getInstance();
    final peers = prefs.getStringList(_keyPeers) ?? [];
    peers.remove(nodeId);
    await prefs.setStringList(_keyPeers, peers);
  }
}
