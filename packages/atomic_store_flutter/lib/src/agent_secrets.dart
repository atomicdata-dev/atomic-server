import 'package:atomic_store/atomic_store.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Where an app keeps the agent secret between starts. [AtomicFlutter.open]
/// reads it when no `agentSecret` is passed, and the node writes it on every
/// sign-in and deletes it on sign-out.
abstract interface class AgentSecretStore {
  Future<String?> read(String key);
  Future<void> write(String key, String secret);
  Future<void> delete(String key);

  /// Keeps the secret of an agent that was signed in before, so it can still
  /// be signed in as (see `SignIn.previousSecret`). Stored under `$key.old`,
  /// one per line.
  Future<void> archive(String key, String secret);
}

/// The default: the OS keychain / keystore (`flutter_secure_storage`).
/// On macOS it uses the login keychain, which needs no entitlement.
///
/// With a [keychainGroup], iOS and macOS keep the secret in that shared
/// keychain access group, so every app of the same team that names the same
/// group reads the same agent. On macOS this switches to the data protection
/// keychain, which needs the `keychain-access-groups` entitlement and a fixed
/// signing team. Android and the other platforms have no shared keystore: the
/// secret stays per app there and [keychainGroup] is ignored.
class SecureAgentSecrets implements AgentSecretStore {
  const SecureAgentSecrets({this.keychainGroup});

  /// The keychain access group, for example `ABCDE12345.io.example.shared`
  /// (team id prefix included), or null for the per-app keychain.
  final String? keychainGroup;

  FlutterSecureStorage get _storage => FlutterSecureStorage(
        iOptions: IOSOptions(groupId: keychainGroup),
        mOptions: MacOsOptions(
            groupId: keychainGroup,
            useDataProtectionKeyChain: keychainGroup != null),
      );

  /// A refused or cancelled keychain prompt is a [StoreException]: making a
  /// new agent instead would quietly split the person in two.
  @override
  Future<String?> read(String key) async {
    try {
      return await _storage.read(key: key);
    } on PlatformException catch (e) {
      throw StoreException(
          StoreErrorKind.storage,
          'This app may not read its saved account from the keychain '
          '(${e.message ?? e.code}). Start it again and allow access.');
    }
  }

  @override
  Future<void> write(String key, String secret) =>
      _storage.write(key: key, value: secret);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);

  @override
  Future<void> archive(String key, String secret) async {
    final old = (await _storage.read(key: '$key.old'))?.split('\n') ?? [];
    if (old.contains(secret)) return;
    await _storage.write(key: '$key.old', value: [...old, secret].join('\n'));
  }
}

/// Keeps secrets in memory only: for tests, or an app that wants a new
/// identity every start.
class MemoryAgentSecrets implements AgentSecretStore {
  final Map<String, String> values = {};

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String secret) async => values[key] = secret;

  @override
  Future<void> delete(String key) async => values.remove(key);

  @override
  Future<void> archive(String key, String secret) async {
    final old = values['$key.old'];
    values['$key.old'] = old == null ? secret : '$old\n$secret';
  }
}
