import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'atomic_client.dart';
import 'own_profile.dart';
import 'profile_picture_picker.dart';
import 'atomic_auth.dart';
import 'server_info.dart';
import 'session.dart';
import '../screens/pair_screen.dart';

/// The app keeps its existing native bridge, secure storage and transport.
/// Only the UI is shared with other Atomic applications.
class AppSettingsBackend extends shared.AtomicSettingsBackend {
  @override
  Future<shared.AtomicIdentity?> getActiveAgent() async {
    final agent = await AtomicClient.getActiveAgent();
    if (agent == null) return null;
    try {
      final p = await OwnProfile.load();
      return shared.AtomicIdentity(
        subject: agent.subject,
        name: p.name ?? agent.name,
        description: p.description,
        imageUrl: p.imageUrl,
        imageBytes: p.imageBytes,
        emoji: p.emoji,
      );
    } catch (e) {
      debugPrint('Own profile not read: $e');
      return shared.AtomicIdentity(subject: agent.subject, name: agent.name);
    }
  }

  @override
  Future<void> Function(
      {required String name,
      required String description,
      shared.ProfilePicture? picture,
      bool? removePicture}) get saveProfile => (
          {required name,
          required description,
          shared.ProfilePicture? picture,
          bool? removePicture}) async {
        // The picture first: the File must exist before the profile names it.
        final icon = picture != null
            ? await AtomicClient.uploadAgentPicture(
                picture.name, picture.mimeType, picture.bytes)
            : (removePicture == true ? '' : null);
        await AtomicClient.setAgentProfile(name, description, icon: icon);
      };

  @override
  Future<shared.ProfilePicture?> Function() get pickProfilePicture =>
      pickProfileImage;

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
  Future<List<Map<String, String>>> liveUnsavedPeers() async =>
      AtomicClient.liveUnsavedPeers();
  @override
  Future<void> removeKnownPeer(String nodeId) =>
      AtomicClient.removeKnownPeer(nodeId);
  @override
  Future<void> pair(BuildContext context) async {
    await PairScreen.show(context);
  }

  @override
  shared.PeerSearchInfo? peerSearchStatus() =>
      shared.PeerSearchInfo.fromJson(AtomicClient.peerSearchStatus());
  @override
  void Function() get searchAgain => AtomicClient.peerSearchAgain;

  static const _statsTtl = Duration(seconds: 30);
  static shared.StoreStats? _stats;
  static DateTime? _statsAt;
  static Future<shared.StoreStats?>? _statsRunning;

  /// Counted off the UI thread by the bridge, kept for 30 s, and one count at
  /// a time however often the card asks.
  @override
  Future<shared.StoreStats?> storeStats({bool refresh = false}) {
    final at = _statsAt;
    if (!refresh &&
        _stats != null &&
        at != null &&
        DateTime.now().difference(at) < _statsTtl) {
      return Future.value(_stats);
    }
    return _statsRunning ??= () async {
      try {
        final stats =
            shared.StoreStats.fromJson(await AtomicClient.storeStatsJson());
        _stats = stats;
        _statsAt = DateTime.now();
        return stats;
      } finally {
        _statsRunning = null;
      }
    }();
  }

  @override
  shared.DeviceInfo? deviceInfo() {
    final info = AtomicClient.deviceInfoJson();
    String? platform;
    try {
      platform = _platformName(Platform.operatingSystem);
    } catch (_) {
      // dart:io has no platform on the web.
    }
    return shared.DeviceInfo(
      platform: platform,
      appVersion: info['version'] as String?,
      arch: info['arch'] as String?,
    );
  }

  static String _platformName(String os) => switch (os) {
        'android' => 'Android',
        'ios' => 'iOS',
        'macos' => 'macOS',
        'windows' => 'Windows',
        'linux' => 'Linux',
        _ => os,
      };

  @override
  shared.AtomicServerBackend get servers => AppServerBackend();
  @override
  Future<void> Function() get signOut => AtomicSession.clear;
}

class AppServerBackend extends shared.AtomicServerBackend {
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

  /// The servers the active drive's pkarr record names and that prove they
  /// hold it: added to the known list (not put in use), so a server that hosts
  /// the drive (an atomic.place node, a self-hosted one) is listed without
  /// being typed in.
  @override
  Future<List<String>> discoverServers() async {
    final drive = AtomicClient.getActiveDrive();
    if (drive == null) return const [];
    final found = await AtomicClient.verifiedDriveOrigins(drive);
    for (final origin in found) {
      await AtomicSession.addKnownServer(origin);
    }
    return found;
  }
}
