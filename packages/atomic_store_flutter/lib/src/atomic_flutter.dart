import 'package:atomic_store/atomic_store.dart';

import 'agent_secrets.dart';
import 'bridge_store_backend.dart';
import 'drives.dart';
import 'identity.dart';
import 'peers.dart';
import 'server_sync.dart';
import 'sharing.dart';
import 'init_native.dart' if (dart.library.js_interop) 'init_web.dart' as impl;
import '../bridge/api/error.dart' as bridge;
import '../bridge/api/resources.dart' as bridge;

/// Entry point of `package:atomic_store_flutter`.
///
/// ```dart
/// await AtomicFlutter.init();                      // once, in main()
/// final node = await AtomicFlutter.open(path: dir, agentName: 'Alice');
/// final doc = node.store.newResource(
///     isA: [Classes.documentV2], props: {Props.name: 'Hello'});
/// await doc.save();
/// ```
abstract final class AtomicFlutter {
  static Future<void>? _init;

  /// Loads the native library. Call it once before anything else (after
  /// `WidgetsFlutterBinding.ensureInitialized()`). Calling it again returns
  /// the first call's result: the library only loads once per process.
  static Future<void> init() =>
      _init ??= impl.initRustBridge().onError((e, st) {
        _init = null; // let the caller retry after a failed load
        Error.throwWithStackTrace(e!, st);
      });

  /// Opens (creating when missing) the local node in the directory [path]
  /// and returns a [Store] on it.
  ///
  /// - First run: pass no [agentSecret]. A new agent called [agentName] and
  ///   its private drive are created; keep [AtomicNode.agentSecret] (secure
  ///   storage) and pass it back on the next start.
  /// - Later runs: pass the saved [agentSecret]; the store works in [drive],
  ///   or in the drive the node was last on.
  /// - A new device (new [path]) for an existing agent: pass the
  ///   [agentSecret] and no [drive]. The secret names the agent's private
  ///   drive and the store works in it; [AtomicNode.driveNeedsSync] is `true`
  ///   until [AtomicNode.connect] has fetched that drive from a server.
  ///
  /// Without an [agentSecret], the one [secretStore] kept for this [path] is
  /// used, so reopening keeps the same agent (the Rust node forgets its agent
  /// when the process ends). The secret in use is written back to
  /// [secretStore] on open and on every [Identity.create], [Identity.signIn]
  /// and [Identity.signOut] (which deletes it). Pass [MemoryAgentSecrets] to
  /// keep nothing.
  ///
  /// A file is opened once per process: call this once and keep the result.
  static Future<AtomicNode> open({
    required String path,
    String? agentSecret,
    String agentName = 'Me',
    String? drive,
    AgentSecretStore secretStore = const SecureAgentSecrets(),
  }) async {
    await init();
    final key = 'atomic_agent:$path';
    agentSecret ??= await secretStore.read(key);
    try {
      final handle = await bridge.AtomicStore.open(
          path: path, agentSecret: agentSecret, drive: drive);
      var secret = agentSecret;
      var workingDrive = handle.drive();
      var needsSync = false;
      if (secret != null && workingDrive == null) {
        // No drive given and none remembered by this file: a fresh device.
        // Take the drive the secret carries, as `loadAgent` does.
        final loaded = await handle.loadAgent(secret: secret);
        needsSync = loaded.needsSync;
        workingDrive = handle.drive();
      }
      if (secret == null) {
        final created = await handle.setup(name: agentName);
        secret = created.agentSecret;
        workingDrive = created.drive;
      }
      await secretStore.write(key, secret);
      return AtomicNode._(
        handle,
        Store(backend: BridgeStoreBackend(handle), drive: workingDrive),
        secret,
        workingDrive,
        needsSync,
        secretStore,
        key,
      );
    } on bridge.AtomicError catch (e) {
      throw storeExceptionFromBridge(e);
    }
  }
}

/// What the account UI needs of a node. [AtomicNode] is one; tests pass a
/// `FakeNode` from `package:atomic_store_flutter/testing.dart`.
abstract interface class AtomicParts {
  Store get store;
  Identity get identity;
  Drives get drives;
  ServerSync get sync;
  Peers get peers;
  Sharing get sharing;
}

/// An open local node: the [store] to read and write through, the agent that
/// signs, and everything around it an app needs: [identity], [drives], [sync]
/// with a server, [peers] (device to device) and [sharing].
///
/// A node on its own is local only. Which of the parts you use is up to you;
/// an app that never pairs devices never starts [peers].
class AtomicNode implements AtomicParts {
  AtomicNode._(this.handle, this.store, String agentSecret, String? drive,
      bool driveNeedsSync, this._secrets, this._secretKey)
      : _agentSecret = agentSecret,
        _driveNeedsSync = driveNeedsSync {
    identity = BridgeIdentity(handle, store,
        (secret, drive, needsSync, previousSecret) async {
      _agentSecret = secret;
      _driveNeedsSync = needsSync;
      if (secret == null) {
        await _secrets.delete(_secretKey);
      } else {
        await _secrets.write(_secretKey, secret);
      }
      if (previousSecret != null) {
        await _secrets.archive(_secretKey, previousSecret);
      }
    }, agentSecret);
    drives = BridgeDrives(handle, store);
    sync = BridgeServerSync(handle, store);
    peers = BridgePeers(handle);
    sharing = Sharing(
        store,
        (target, write, expiresAt, maxUsages) => handle.createInviteToken(
            target: target,
            write: write,
            expiresAt: expiresAt,
            maxUsages: maxUsages));
  }

  /// The raw bridge handle, for what the typed parts do not cover (files,
  /// history, the assistant).
  final bridge.AtomicStore handle;

  /// The Dart `Store`, working in [drive].
  @override
  final Store store;

  final AgentSecretStore _secrets;
  final String _secretKey;

  String? _agentSecret;
  bool _driveNeedsSync;

  /// Who signs: create or load an agent, sign out, the profile. Keeping the
  /// secret is the app's job (see [Identity]).
  @override
  late final Identity identity;

  /// The agent's drives: list, create, switch. [store] follows a switch.
  @override
  late final Drives drives;

  /// Sync with an Atomic Server: connect on start, status, finding the server
  /// that hosts a drive.
  @override
  late final ServerSync sync;

  /// Sync between devices over Iroh, with QR pairing. Peers belong to the
  /// process: see [Peers].
  @override
  late final Peers peers;

  /// Who may read or write a resource, and invite links.
  @override
  late final Sharing sharing;

  /// The secret of the signing agent. Persist it: it is the identity. Empty
  /// after [Identity.signOut].
  String get agentSecret => _agentSecret ?? '';

  /// The drive [store] works in (a subject), when there is one. Follows
  /// [Drives.switchTo], [Identity.signIn] and [Identity.create].
  String? get drive => store.drive;

  /// `true` when the drive [store] works in is not on this device yet (after
  /// [open] with a secret from another device, or [Identity.signIn]): the
  /// store is empty until [connect] fetches it from a server or [peers] pairs
  /// with a device that has it.
  bool get driveNeedsSync => _driveNeedsSync;

  /// The signing agent's subject (`did:ad:agent:...`).
  String? get agentSubject => handle.agentSubject();

  /// Signs in at the server [serverOrigin] (for example
  /// `https://example.com`), subscribes to [drive] and keeps both in sync:
  /// local writes are sent and the server's changes are applied, so a
  /// `store.watch` sees them. Without it the node is local only.
  /// Same as `sync.connect`.
  Future<void> connect(String serverOrigin) => sync.connect(serverOrigin);

  /// Stops the server session. Writes wait on disk until [connect] again.
  Future<void> disconnect() => sync.disconnect();
}
