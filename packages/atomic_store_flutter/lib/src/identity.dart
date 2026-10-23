import 'package:atomic_store/atomic_store.dart';

import '../bridge/api/error.dart' as bridge;
import '../bridge/api/resources.dart' as bridge;
import 'bridge_store_backend.dart' show storeExceptionFromBridge;

/// The profile of the signed-in agent.
class Profile {
  const Profile({
    required this.subject,
    this.name = '',
    this.description = '',
    this.emoji,
    this.imageUrl,
  });

  final String subject;
  final String name;
  final String description;
  final String? emoji;
  final String? imageUrl;
}

/// What a sign-in found.
class SignIn {
  const SignIn(
      {required this.agentSubject,
      required this.drive,
      required this.needsSync});

  final String agentSubject;

  /// The drive the store now works in (the agent's private drive unless the
  /// secret named another).
  final String? drive;

  /// That drive is not on this device yet: connect to a server that hosts it
  /// (`node.sync`), or pair with a device that has it (`node.peers`).
  final bool needsSync;
}

/// Who signs: an agent, which is an Ed25519 key pair and nothing else. There
/// is no account and no password; the secret **is** the identity.
///
/// **Keeping the secret is the app's job.** The package never writes it
/// anywhere: put it in secure storage (for example `flutter_secure_storage`)
/// and pass it back to `AtomicFlutter.open(agentSecret: ...)` next start, or
/// to [signIn]. Whoever has the secret is the agent.
///
/// ```dart
/// final made = await node.identity.create('Alice');   // new agent + drive
/// await storage.write(key: 'agent', value: made.secret);
/// // elsewhere, with the secret:
/// final found = await node.identity.signIn(secret);
/// if (found.needsSync) await node.sync.resume(origin);
/// ```
abstract interface class Identity {
  /// The signing agent (`did:ad:agent:...`), `null` when signed out.
  String? get subject;

  /// The signing agent's secret, `null` when signed out. Sensitive.
  String? get secret;

  /// Makes a new agent called [name] and its private drive, signs as it from
  /// now on and works in the drive. Returns the new secret, to keep.
  Future<({String secret, String agentSubject, String drive})> create(
      String name);

  /// Signs as the agent of [secret] from now on. The store works in the drive
  /// the secret names; when this device does not hold it yet ([SignIn.needsSync]),
  /// the store is empty until it syncs. Throws a `StoreException` for a text
  /// that is not an agent secret.
  Future<SignIn> signIn(String secret);

  /// Stops signing, closes the server session and forgets the agent in this
  /// process. The data stays in the file; the secret signs in again. Writes
  /// fail until [signIn] or [create].
  Future<void> signOut();

  /// The signed-in agent's profile (name, description, picture).
  Future<Profile> profile();

  /// Saves the profile name (not empty) and description (empty removes it) as
  /// a signed commit by the agent; it syncs like any edit.
  Future<void> updateProfile({required String name, String description = ''});
}

/// [Identity] over one node's handle. [onChange] tells the node its secret and
/// drive changed.
class BridgeIdentity implements Identity {
  BridgeIdentity(this._handle, this._store, this._onChange, String? secret)
      : _secret = secret;

  final bridge.AtomicStore _handle;
  final Store _store;
  final void Function(String? secret, String? drive, bool needsSync) _onChange;
  String? _secret;

  Future<T> _guard<T>(Future<T> Function() run) async {
    try {
      return await run();
    } on bridge.AtomicError catch (e) {
      throw storeExceptionFromBridge(e);
    }
  }

  @override
  String? get subject => _handle.agentSubject();

  @override
  String? get secret => _secret;

  @override
  Future<({String secret, String agentSubject, String drive})> create(
      String name) async {
    final made = await _guard(() => _handle.setup(name: name));
    _secret = made.agentSecret;
    _store.drive = made.drive;
    _onChange(made.agentSecret, made.drive, false);
    return (
      secret: made.agentSecret,
      agentSubject: made.agentSubject,
      drive: made.drive
    );
  }

  @override
  Future<SignIn> signIn(String secret) async {
    final loaded = await _guard(() => _handle.loadAgent(secret: secret));
    _secret = secret;
    final drive = _handle.drive();
    _store.drive = drive;
    _store.clearCache();
    _onChange(secret, drive, loaded.needsSync);
    return SignIn(
        agentSubject: loaded.agentSubject,
        drive: drive,
        needsSync: loaded.needsSync);
  }

  @override
  Future<void> signOut() async {
    await _handle.signOut();
    _secret = null;
    _store.clearCache();
    _onChange(null, _store.drive, false);
  }

  @override
  Future<Profile> profile() async {
    final p = await _guard(() => _handle.profile());
    return Profile(
        subject: p.subject,
        name: p.name,
        description: p.description,
        emoji: p.emoji,
        imageUrl: p.imageUrl);
  }

  @override
  Future<void> updateProfile({required String name, String description = ''}) =>
      _guard(() => _handle.setProfile(name: name, description: description));
}
