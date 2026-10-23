import 'dart:async';

import 'package:atomic_store/atomic_store.dart';

import '../bridge/api/error.dart' as bridge;
import '../bridge/api/node.dart' as bridge;
import '../bridge/api/resources.dart' as bridge;
import 'bridge_store_backend.dart' show storeExceptionFromBridge;

/// A drive of the signed-in agent.
class DriveInfo {
  const DriveInfo({
    required this.subject,
    required this.name,
    this.emoji,
    this.unreadable = false,
    this.active = false,
  });

  final String subject;
  final String name;

  /// The drive's own icon, if it has one.
  final String? emoji;

  /// A server refused this agent the drive.
  final bool unreadable;

  /// The drive the store works in.
  final bool active;

  @override
  bool operator ==(Object other) =>
      other is DriveInfo &&
      other.subject == subject &&
      other.name == name &&
      other.emoji == emoji &&
      other.unreadable == unreadable &&
      other.active == active;

  @override
  int get hashCode => Object.hash(subject, name, emoji, unreadable, active);

  @override
  String toString() => 'DriveInfo($name, $subject${active ? ', active' : ''})';
}

/// The agent's drives: the top-level containers of its data. The node's
/// `store` works in one of them; switching follows everywhere.
///
/// ```dart
/// final drives = await node.drives.list();
/// final work = await node.drives.create('Work');   // now the current drive
/// await node.drives.switchTo(drives.first.subject);
/// node.drives.watchCurrent().listen((d) => print(d));
/// ```
abstract interface class Drives {
  /// The drive the store works in now.
  String? get current;

  /// [current] now and after every [create] or [switchTo].
  Stream<String?> watchCurrent();

  /// The agent's drives, the current one and the recently used first.
  Future<List<DriveInfo>> list();

  /// Creates a private drive named [name] and makes it the current one.
  Future<DriveInfo> create(String name);

  /// Works in [subject] from now on, and remembers it for the next start.
  /// `node.store.drive` follows.
  Future<void> switchTo(String subject);
}

/// [Drives] over one node's handle and its [Store].
class BridgeDrives implements Drives {
  BridgeDrives(this._handle, this._store);

  final bridge.AtomicStore _handle;
  final Store _store;
  final _changes = StreamController<String?>.broadcast();

  Future<T> _guard<T>(Future<T> Function() run) async {
    try {
      return await run();
    } on bridge.AtomicError catch (e) {
      throw storeExceptionFromBridge(e);
    }
  }

  @override
  String? get current => _store.drive;

  @override
  Stream<String?> watchCurrent() {
    StreamSubscription<String?>? sub;
    late final StreamController<String?> controller;
    controller = StreamController<String?>(
      onListen: () {
        controller.add(current);
        sub = _changes.stream.listen(controller.add);
      },
      onCancel: () => sub?.cancel(),
    );
    return controller.stream;
  }

  @override
  Future<List<DriveInfo>> list() async =>
      drivesFromBridge(await _guard(() => _handle.listDrivesInfo()));

  @override
  Future<DriveInfo> create(String name) async {
    final subject = await _guard(() => _handle.newDrive(name: name));
    _follow(subject);
    return DriveInfo(subject: subject, name: name, active: true);
  }

  @override
  Future<void> switchTo(String subject) async {
    await _guard(() async => _handle.switchDrive(drive: subject));
    _follow(subject);
  }

  void _follow(String subject) {
    _store.drive = subject;
    _changes.add(subject);
  }
}

List<DriveInfo> drivesFromBridge(Iterable<bridge.DriveSummary> rows) => [
      for (final d in rows)
        DriveInfo(
            subject: d.subject,
            name: d.name,
            emoji: d.emoji,
            unreadable: d.unreadable,
            active: d.active)
    ];
