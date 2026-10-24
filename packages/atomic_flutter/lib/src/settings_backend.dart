import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'device_stats.dart';
import 'server_info.dart';

/// Public identity only. Secrets are retrieved on explicit user action.
class AtomicIdentity {
  const AtomicIdentity({
    required this.subject,
    this.name,
    this.description,
    this.imageUrl,
    this.imageBytes,
    this.emoji,
  });
  final String subject;
  final String? name;
  final String? description;

  /// The agent's picture (the download URL of its `icon` File), if any.
  final String? imageUrl;

  /// The picture's bytes, when this device holds the picture's file.
  final Uint8List? imageBytes;

  /// The agent's emoji icon, if it has one and no picture.
  final String? emoji;
}

/// A picture the person picked for their profile.
class ProfilePicture {
  const ProfilePicture(
      {required this.name, required this.mimeType, required this.bytes});
  final String name;
  final String mimeType;
  final Uint8List bytes;
}

/// Host-owned persistence, authentication and transport for the settings UI.
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

  /// Devices connected right now that are not paired (they dialed us). Shown
  /// only; nothing about them is saved. Maps with `node_id` and `name`.
  Future<List<Map<String, String>>> liveUnsavedPeers() async => const [];
  Future<void> removeKnownPeer(String nodeId);
  Future<void> pair(BuildContext context);

  /// Syncs with one paired device now and says what moved, in a line to show
  /// ("Received 3 resources from Polle's iPhone"). Null: no "Sync now".
  Future<String> Function(String nodeId)? get syncPeer => null;

  /// Optional capabilities; unavailable actions are not displayed.
  AtomicServerBackend? get servers => null;
  Future<void> Function()? get signOut => null;

  /// Signs in as the agent of a pasted secret and says what happened, in a
  /// line to show. Throws for a text that is no secret. Null: no such row.
  Future<String> Function(String secret)? get signInWithSecret => null;

  /// A link that invites someone to the active workspace. Null: no invite row.
  Future<String> Function({required bool canEdit})? get inviteLink => null;

  /// The active agent now and after every change of it, here or on another
  /// device, so a renamed profile shows without a button. Null: no live
  /// updates. Asked again after every load (a sign-in is a new agent).
  Stream<AtomicIdentity?>? watchActiveAgent() => null;

  /// Saves the agent's own profile (a commit by the agent, synced like any
  /// edit). Without it the profile is only shown, not edited natively.
  ///
  /// [picture] replaces the profile picture; [removePicture] takes it away.
  /// With neither the picture stays as it is.
  Future<void> Function(
      {required String name,
      required String description,
      ProfilePicture? picture,
      bool? removePicture})? get saveProfile => null;

  /// Lets the person pick a picture (null when they cancel). Without it the
  /// profile editor does not offer to change the picture.
  Future<ProfilePicture?> Function()? get pickProfilePicture => null;

  /// What the search for this account's other devices is doing, or null when
  /// the host does not search (then nothing is shown).
  PeerSearchInfo? peerSearchStatus() => null;

  /// Look for the other devices now. Null: no "Search again" button.
  void Function()? get searchAgain => null;

  /// How much of the person's data this device holds. Slow on a big store: the
  /// card asks lazily; the host may cache, and [refresh] asks for a fresh count. Null: the host cannot say (nothing shown).
  Future<StoreStats?> storeStats({bool refresh = false}) async => null;

  /// What this build and platform are; null when unknown.
  DeviceInfo? deviceInfo() => null;
}

/// The device search's state (`peer_search_status` in the bridge): what it is
/// doing, in a line to show, and why, for a details line.
class PeerSearchInfo {
  const PeerSearchInfo({
    required this.state,
    required this.message,
    this.detail,
    this.retryInSecs,
    this.lastCheckedMs,
  });

  /// `starting`, `searching`, `no_peers_yet`, `connected` or `failed`.
  final String state;
  final String message;
  final String? detail;
  final int? retryInSecs;
  final int? lastCheckedMs;

  bool get busy => state == 'starting' || state == 'searching';
  bool get connected => state == 'connected';
  bool get failed => state == 'failed';

  static PeerSearchInfo? fromJson(Map<String, dynamic> json) {
    final state = json['state'];
    if (state is! String) return null;
    return PeerSearchInfo(
      state: state,
      message: json['message'] as String? ?? '',
      detail: json['detail'] as String?,
      retryInSecs: (json['retry_in_secs'] as num?)?.toInt(),
      lastCheckedMs: (json['last_checked_ms'] as num?)?.toInt(),
    );
  }
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

  /// Servers found for the active drive without being typed in (its pkarr
  /// record's https origins whose genesis verified), already added to the
  /// known list by the host. The section shows them when this returns.
  Future<List<String>> discoverServers() async => const [];
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
