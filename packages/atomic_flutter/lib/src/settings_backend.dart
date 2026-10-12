import 'package:flutter/material.dart';
import 'server_info.dart';

/// Public identity only. Secrets are retrieved on explicit user action.
class AtomicIdentity {
  const AtomicIdentity({required this.subject, this.name});
  final String subject;
  final String? name;
}

/// Host-owned persistence, authentication and transport for the Canvas UI.
/// Implementations must throw on failure; widgets only update after success.
/// No database, native bridge, global singleton or audio thread is owned here.
abstract class AtomicSettingsBackend {
  Future<AtomicIdentity?> getActiveAgent();
  Future<String> exportSecret();
  Future<List<String>> listDrives();
  String? getActiveDrive();
  Future<String> getDriveName(String drive);
  Future<void> createDrive(String name);

  /// Persist the selection and switch any application-specific data atomically.
  Future<void> switchDrive(String drive);
  Future<String?> getPeerId();
  Future<String> getDeviceName();
  Future<void> setDeviceName(String name);
  Future<List<Map<String, String>>> getKnownPeers();
  Future<Set<String>> livePeerIds();
  Future<void> removeKnownPeer(String nodeId);
  Future<void> pair(BuildContext context);

  /// Optional capabilities; unavailable actions are not displayed.
  AtomicServerBackend? get servers => null;
  Future<void> Function(BuildContext context)? get signInWithAccount => null;
  Future<void> Function()? get syncAccount => null;
  Future<void> Function()? get useLocalProjects => null;
  String? get accountStatus => null;
  Future<void> Function()? get signOut => null;
  Future<void> Function(BuildContext context)? get signIn => null;
}

/// Optional always-on server support. The host keeps credentials and signed
/// HTTP reads; the shared widgets receive only public server/usage data.
abstract class AtomicServerBackend {
  Future<List<String>> knownServers();
  Future<String?> activeServer();
  Future<ServerInfo> serverInfo(String url);
  Future<DriveUsage?> driveUsage(String url);
  Future<void> switchTo(String url);
  Future<void> add(String url);
  Future<void> remove(String url);
  Future<int> pushWorkspace(String url);
}

bool isLiveAtomicPeer(String known, Set<String> live) {
  String normalize(String id) {
    var value = id.trim().toLowerCase();
    if (value.startsWith('atomic:node:')) {
      value = 'did:ad:node:${value.substring(12)}';
    }
    if (value.startsWith('did:ad:node:')) {
      value = value.substring(12);
      if (value.length > 64) value = value.substring(0, 64);
    }
    if (value.startsWith('iroh:')) value = value.substring(5);
    return value;
  }

  return live.any((id) => normalize(id) == normalize(known));
}
