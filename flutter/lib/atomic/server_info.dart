/// What a server says about itself, and what a drive costs on it.
///
/// Plain HTTP against two endpoints every atomic-server has, so this works
/// against any node — self-hosted included — with no bridge call:
///
///   GET /server       → a `Server` resource (JSON-AD). Public.
///   GET /drive-usage  → a drive's resource count + bytes. Signed; the server
///                       checks read access to the drive.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

import 'atomic_auth.dart';

/// Property URLs of the `Server` class. Handwritten rather than generated —
/// this describes the node, not anything in a drive. Keep in step with
/// `lib/src/urls.rs` and the data-browser's `serverOntology.ts`.
class ServerProps {
  static const nodeId = 'https://atomicdata.dev/properties/server/nodeId';
  static const version = 'https://atomicdata.dev/properties/server/version';
  static const managed = 'https://atomicdata.dev/properties/server/managed';
  static const portalUrl = 'https://atomicdata.dev/properties/server/portalUrl';
}

/// A node's own description. Fields are null when the node does not report
/// them: an older server, or one with no peer-to-peer transport running.
class ServerInfo {
  const ServerInfo({
    this.nodeId,
    this.version,
    this.managed = false,
    this.portalUrl,
  });

  /// This node's `did:ad:node:...` identity, if its p2p transport is running.
  final String? nodeId;
  final String? version;

  /// Whether the node reports to a control plane, rather than being self-hosted.
  final bool managed;

  /// Where a managed node is administered.
  final String? portalUrl;

  static const unknown = ServerInfo();

  factory ServerInfo.fromJsonAd(Map<String, dynamic> json) {
    String? read(String prop) {
      final value = json[prop];

      return value is String && value.isNotEmpty ? value : null;
    }

    return ServerInfo(
      nodeId: read(ServerProps.nodeId),
      version: read(ServerProps.version),
      managed: json[ServerProps.managed] == true,
      portalUrl: read(ServerProps.portalUrl),
    );
  }
}

/// What a drive stores on a node.
class DriveUsage {
  const DriveUsage({
    this.driveName,
    required this.resourceCount,
    required this.blobBytes,
    required this.loroBytes,
  });

  final String? driveName;
  final int resourceCount;

  /// Bytes held by file contents.
  final int blobBytes;

  /// Bytes held by the CRDT documents behind the resources.
  final int loroBytes;

  int get totalBytes => blobBytes + loroBytes;
}

/// Asks `serverUrl` what it is. Returns [ServerInfo.unknown] when the node is
/// unreachable, or too old to describe itself.
Future<ServerInfo> fetchServerInfo(String serverUrl,
    {http.Client? client}) async {
  if (serverUrl.isEmpty) {
    return ServerInfo.unknown;
  }

  final http.Client httpClient = client ?? http.Client();

  try {
    final response = await httpClient.get(
      Uri.parse('$serverUrl/server'),
      headers: const {'Accept': 'application/ad+json'},
    );

    if (response.statusCode != 200) {
      return ServerInfo.unknown;
    }

    return ServerInfo.fromJsonAd(
      jsonDecode(response.body) as Map<String, dynamic>,
    );
  } catch (_) {
    return ServerInfo.unknown;
  } finally {
    if (client == null) httpClient.close();
  }
}

/// What `driveSubject` stores on `serverUrl`. Null when the node is
/// unreachable, the agent may not read the drive, or the drive is not there.
Future<DriveUsage?> fetchDriveUsage(
  String serverUrl,
  String driveSubject,
  AtomicAgent agent, {
  http.Client? client,
}) async {
  if (serverUrl.isEmpty || driveSubject.isEmpty) {
    return null;
  }

  final url = Uri.parse('$serverUrl/drive-usage')
      .replace(queryParameters: {'subject': driveSubject});
  final http.Client httpClient = client ?? http.Client();

  try {
    // Sign the URL being fetched, query string and all — the server rebuilds
    // the signed message from the request it received.
    final response = await httpClient.get(
      url,
      headers: {
        ...signedHeaders(url.toString(), agent),
        'Accept': 'application/json',
      },
    );

    if (response.statusCode != 200) {
      return null;
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final name = json['name'];

    return DriveUsage(
      driveName: name is String && name.isNotEmpty ? name : null,
      resourceCount: (json['resourceCount'] as num?)?.toInt() ?? 0,
      blobBytes: (json['blobBytes'] as num?)?.toInt() ?? 0,
      loroBytes: (json['loroBytes'] as num?)?.toInt() ?? 0,
    );
  } catch (_) {
    return null;
  } finally {
    if (client == null) httpClient.close();
  }
}

/// Bytes as a person reads them.
String formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';

  const units = ['KB', 'MB', 'GB', 'TB'];
  var value = bytes / 1024;
  var unit = 0;

  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }

  return '${value.toStringAsFixed(value < 10 ? 1 : 0)} ${units[unit]}';
}
