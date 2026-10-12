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
