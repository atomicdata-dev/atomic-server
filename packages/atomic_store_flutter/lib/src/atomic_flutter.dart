import 'package:atomic_store/atomic_store.dart';

import 'bridge_store_backend.dart';
import 'init_native.dart' if (dart.library.js_interop) 'init_web.dart' as impl;
import '../bridge/api/error.dart' as bridge;
import '../bridge/api/resources.dart' as bridge;

/// Entry point of `package:atomic_store_flutter`.
///
/// ```dart
/// await AtomicFlutter.init();                      // once, in main()
/// final node = await AtomicFlutter.open(path: dir, agentName: 'Alice');
/// final doc = node.store.newResource(
///     isA: [Classes.document], props: {Props.name: 'Hello'});
/// await doc.save();
/// ```
abstract final class AtomicFlutter {
  static Future<void>? _init;

  /// Loads the native library. Call it once before anything else (after
  /// `WidgetsFlutterBinding.ensureInitialized()`). Calling it again returns
  /// the first call's result: the library only loads once per process.
  static Future<void> init() => _init ??= impl.initRustBridge().onError((e, st) {
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
  ///
  /// A file is opened once per process: call this once and keep the result.
  static Future<AtomicNode> open({
    required String path,
    String? agentSecret,
    String agentName = 'Me',
    String? drive,
  }) async {
    await init();
    try {
      final handle = await bridge.AtomicStore.open(
          path: path, agentSecret: agentSecret, drive: drive);
      var secret = agentSecret;
      var workingDrive = handle.drive();
      if (secret == null) {
        final created = await handle.setup(name: agentName);
        secret = created.agentSecret;
        workingDrive = created.drive;
      }
      return AtomicNode._(
        handle,
        Store(backend: BridgeStoreBackend(handle), drive: workingDrive),
        secret,
        workingDrive,
      );
    } on bridge.AtomicError catch (e) {
      throw storeExceptionFromBridge(e);
    }
  }
}

/// An open local node: the [store] to read and write through, the agent that
/// signs, and the sync switch.
class AtomicNode {
  AtomicNode._(this.handle, this.store, this.agentSecret, this.drive);

  /// The raw bridge handle, for what [Store] does not cover (peers, files,
  /// history, the assistant).
  final bridge.AtomicStore handle;

  /// The Dart `Store`, working in [drive].
  final Store store;

  /// The secret of the signing agent. Persist it: it is the identity.
  final String agentSecret;

  /// The drive [store] works in (a subject), when there is one.
  final String? drive;

  /// The signing agent's subject (`did:ad:agent:...`).
  String? get agentSubject => handle.agentSubject();

  /// Signs in at the server [serverOrigin] (for example
  /// `https://example.com`), subscribes to [drive] and keeps both in sync:
  /// local writes are sent and the server's changes are applied, so a
  /// `store.watch` sees them. Without it the node is local only.
  Future<void> connect(String serverOrigin) async {
    try {
      await handle.openWsSync(serverOrigin: serverOrigin);
    } on bridge.AtomicError catch (e) {
      throw storeExceptionFromBridge(e);
    }
  }

  /// Stops the server session. Writes wait on disk until [connect] again.
  Future<void> disconnect() => handle.closeWsSync();
}
