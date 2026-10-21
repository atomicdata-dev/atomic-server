import 'package:atomic_flutter/atomic_flutter.dart'
    show normalizeServerUrl, sameOrigin;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The app's secure storage.
///
/// On macOS it uses the legacy file-based login keychain, not the data
/// protection keychain: that one needs the `keychain-access-groups`
/// entitlement, which needs a provisioning profile, so an ad-hoc or
/// Developer-ID signed build without one fails every access with -34018
/// (errSecMissingEntitlement). iOS and Android are unchanged.
FlutterSecureStorage createSecureStorage() => const FlutterSecureStorage(
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
      mOptions: MacOsOptions(
        useDataProtectionKeyChain: false,
        accessibility: KeychainAccessibility.unlocked,
      ),
    );

/// A sentence for a failed Keychain / secure storage call, in place of the
/// raw `PlatformException(...)` text.
String keychainErrorMessage(Object error) {
  if (error is PlatformException) {
    final code = error.code;
    final text = '${error.message}';
    if (code == '-34018' || text.contains('-34018') ||
        code.contains('34018')) {
      return 'Couldn\u2019t access the Keychain';
    }
    return 'Couldn\u2019t access secure storage';
  }
  return 'Couldn\u2019t access secure storage';
}

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

  static FlutterSecureStorage _secure = createSecureStorage();

  @visibleForTesting
  static set secureStorage(FlutterSecureStorage storage) => _secure = storage;

  /// The secret of this run, when secure storage would not take it: signing
  /// in still works for the session, it just is not remembered.
  static String? _memorySecret;

  /// Set when the last [save] could not store the secret; says why.
  static String? lastSaveWarning;

  @visibleForTesting
  static void resetForTest() {
    _memorySecret = null;
    lastSaveWarning = null;
    _early = null;
  }

  /// Saves the session. A secret that secure storage refuses (an unavailable
  /// Keychain) is kept in memory for this run and reported through
  /// [lastSaveWarning] and the return value (false), not thrown: the person
  /// is signed in, and only has to sign in again next start.
  static Future<bool> save({
    required String serverUrl,
    required String secret,
    String? drive,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyServerUrl, serverUrl);
    var stored = true;
    lastSaveWarning = null;
    _memorySecret = secret;
    try {
      await _secure.write(key: _keySecret, value: secret);
      // Clear any legacy plaintext copy left in SharedPreferences.
      await prefs.remove(_keySecret);
    } catch (e) {
      debugPrint('Saving the secret failed: $e');
      stored = false;
      lastSaveWarning = keychainErrorMessage(e);
    }
    if (isResumableDrive(drive)) {
      await prefs.setString(_keyDrive, drive!);
    }

    await addKnownServer(serverUrl);
    return stored;
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
    String? secure;
    try {
      secure = await _secure.read(key: _keySecret);
    } catch (e) {
      // An unavailable Keychain must not lock the person out or crash the
      // start: treat it as "nothing saved", and use this run's secret if any.
      debugPrint('Reading the secret failed: $e');
      return _memorySecret ?? prefs.getString(_keySecret);
    }
    if (secure != null) return secure;

    final legacy = prefs.getString(_keySecret);
    if (legacy != null) {
      try {
        await _secure.write(key: _keySecret, value: legacy);
        await prefs.remove(_keySecret);
      } catch (e) {
        debugPrint('Migrating the secret failed: $e');
      }
      return legacy;
    }
    return _memorySecret;
  }

  static Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_keyServerUrl);
    _memorySecret = null;
    try {
      await _secure.delete(key: _keySecret);
    } catch (e) {
      debugPrint('Deleting the secret failed: $e');
    }
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
