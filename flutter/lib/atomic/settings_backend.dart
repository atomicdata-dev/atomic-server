import 'package:flutter/material.dart';
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'atomic_client.dart';
import 'atomic_auth.dart';
import 'server_info.dart';
import 'session.dart';
import '../screens/pair_screen.dart';

/// Canvas keeps its existing native bridge, secure storage and transport.
/// Only the UI is shared with other Atomic applications.
class CanvasSettingsBackend extends shared.AtomicSettingsBackend {
  @override
  Future<shared.AtomicIdentity?> getActiveAgent() async {
    final agent = await AtomicClient.getActiveAgent();
    return agent == null
        ? null
        : shared.AtomicIdentity(subject: agent.subject, name: agent.name);
  }

  @override
  Future<String> exportSecret() async {
    final agent = await AtomicClient.getActiveAgent();
    if (agent == null) throw StateError('No active identity');
    return agent.secret;
  }

  @override
  Future<List<String>> listDrives() => AtomicClient.listDrives();
  @override
  String? getActiveDrive() => AtomicClient.getActiveDrive();
  @override
  Future<String> getDriveName(String drive) =>
      AtomicClient.getProperty(drive, 'https://atomicdata.dev/properties/name');
  @override
  Future<void> createDrive(String name) async {
    await AtomicClient.createDrive(name);
  }

  @override
  Future<void> switchDrive(String drive) async {
    await AtomicClient.setActiveDrive(drive);
    await AtomicSession.saveDrive(drive);
  }

  @override
  Future<String?> getPeerId() => AtomicClient.getPeerId();
  @override
  Future<String> getDeviceName() async {
    var name = await AtomicClient.getDeviceName();
    if (name.isEmpty) {
      name = await PairScreen.getDeviceName();
      if (name.isNotEmpty && name != 'localhost') {
        await AtomicClient.setDeviceName(name);
      }
    }
    return name;
  }

  @override
  Future<void> setDeviceName(String name) => AtomicClient.setDeviceName(name);
  @override
  Future<List<Map<String, String>>> getKnownPeers() =>
      AtomicClient.getKnownPeers();
  @override
  Future<Set<String>> livePeerIds() async => AtomicClient.livePeerIds();
  @override
  Future<void> removeKnownPeer(String nodeId) =>
      AtomicClient.removeKnownPeer(nodeId);
  @override
  Future<void> pair(BuildContext context) async {
    await PairScreen.show(context);
  }

  @override
  shared.AtomicServerBackend get servers => CanvasServerBackend();
  @override
  Future<void> Function() get signOut => AtomicSession.clear;
}

class CanvasServerBackend extends shared.AtomicServerBackend {
  @override
  Future<List<String>> knownServers() => AtomicSession.knownServers();
  @override
  Future<String?> activeServer() => AtomicSession.activeServer();
  @override
  Future<shared.ServerInfo> serverInfo(String url) async {
    final info = await fetchServerInfo(url);
    return shared.ServerInfo(
        nodeId: info.nodeId,
        version: info.version,
        managed: info.managed,
        portalUrl: info.portalUrl);
  }

  @override
  Future<shared.DriveUsage?> driveUsage(String url) async {
    final session = await AtomicSession.load();
    if (session == null) return null;
    final drive = AtomicClient.getActiveDrive() ?? session.drive;
    if (drive == null) return null;
    final usage = await fetchDriveUsage(
        url, drive, AtomicAgent.fromSecret(session.secret));
    return usage == null
        ? null
        : shared.DriveUsage(
            driveName: usage.driveName,
            resourceCount: usage.resourceCount,
            blobBytes: usage.blobBytes,
            loroBytes: usage.loroBytes);
  }

  @override
  Future<void> switchTo(String url) async {
    await AtomicClient.closeWsSync();
    await AtomicSession.setActiveServer(url);
    await AtomicClient.openWsSync(url);
  }

  @override
  Future<void> add(String url) => AtomicSession.addKnownServer(url);
  @override
  Future<void> remove(String url) async {
    if (shared.sameOrigin(url, await AtomicSession.activeServer())) {
      await AtomicClient.closeWsSync();
    }
    await AtomicSession.removeKnownServer(url);
  }

  @override
  Future<int> pushWorkspace(String url) => AtomicClient.syncDriveToServer(url);
}
