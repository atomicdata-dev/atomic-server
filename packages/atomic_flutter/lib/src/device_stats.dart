/// What this device holds and runs, for the Sync screen's "This device" card.
/// Everything here comes from the host (the store, the build); a host that
/// cannot tell returns null and the card leaves the line out.
library;

export 'server_info.dart' show formatBytes;

/// A count as a person reads it, the same in every locale: `842`, `1.2k`,
/// `15k`, `3.4M`. Under 1000 the exact number.
String formatCount(int count) {
  if (count < 1000) return '$count';
  const units = ['k', 'M', 'B'];
  var value = count / 1000;
  var unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  // 999.96k would round to "1000k": carry it up instead.
  if (value.toStringAsFixed(value < 10 ? 1 : 0) == '1000' &&
      unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  var text = value.toStringAsFixed(value < 10 ? 1 : 0);
  if (text.endsWith('.0')) text = text.substring(0, text.length - 2);
  return '$text${units[unit]}';
}

/// "1.2 MB · 842 resources", the line under a drive's name.
String formatResources(int count) =>
    '${formatCount(count)} ${count == 1 ? 'resource' : 'resources'}';

/// One drive's share of what the device stores.
class DriveStats {
  const DriveStats({
    required this.subject,
    required this.name,
    required this.resources,
    required this.bytes,
  });

  final String subject;

  /// The drive's name, empty when this device has not read one.
  final String name;
  final int resources;

  /// Bytes of its resources' history and its files.
  final int bytes;

  static DriveStats? fromJson(Object? json) {
    if (json is! Map) return null;
    final subject = json['subject'];
    if (subject is! String) return null;
    return DriveStats(
      subject: subject,
      name: json['name'] as String? ?? '',
      resources: (json['resources'] as num?)?.toInt() ?? 0,
      bytes: (json['bytes'] as num?)?.toInt() ?? 0,
    );
  }
}

/// How much of the person's data is stored on this device.
class StoreStats {
  const StoreStats({
    required this.resources,
    required this.dataBytes,
    required this.drives,
    this.diskBytes,
    this.fileBytes = 0,
  });

  final int resources;

  /// Bytes of the drives' resources and files (what [drives] add up to).
  final int dataBytes;

  /// Bytes the store takes on disk (its file and anything beside it), when the
  /// host could measure it.
  final int? diskBytes;

  /// Of [dataBytes], the bytes of files.
  final int fileBytes;

  /// Biggest first.
  final List<DriveStats> drives;

  /// The total the per-drive bars are a share of.
  int get barTotal => drives.fold(0, (sum, d) => sum + d.bytes);

  /// The bridge's `store_stats` JSON.
  static StoreStats? fromJson(Object? json) {
    if (json is! Map) return null;
    final drives = <DriveStats>[
      for (final d in (json['drives'] as List?) ?? const [])
        if (DriveStats.fromJson(d) case final drive?) drive,
    ]..sort((a, b) {
        final bySize = b.bytes.compareTo(a.bytes);
        return bySize != 0 ? bySize : a.subject.compareTo(b.subject);
      });
    final loro = (json['loro_bytes'] as num?)?.toInt() ?? 0;
    final blob = (json['blob_bytes'] as num?)?.toInt() ?? 0;
    return StoreStats(
      resources: (json['resources'] as num?)?.toInt() ?? 0,
      dataBytes: loro + blob,
      fileBytes: blob,
      diskBytes: (json['disk_bytes'] as num?)?.toInt(),
      drives: drives,
    );
  }
}

/// What this build and platform are.
class DeviceInfo {
  const DeviceInfo({
    this.platform,
    this.osVersion,
    this.appVersion,
    this.arch,
  });

  /// `Android`, `iOS`, `macOS`…
  final String? platform;
  final String? osVersion;

  /// The version of the Atomic engine in this app.
  final String? appVersion;
  final String? arch;

  /// "Android · arm64", empty when nothing is known.
  String get platformLine =>
      [platform, arch].where((s) => s != null && s.isNotEmpty).join(' · ');
}

/// A device's secret-free public id, shortened to start and end: the first 12
/// and last 6 characters when it is longer than 22.
String shortId(String id) => id.length <= 22
    ? id
    : '${id.substring(0, 12)}…${id.substring(id.length - 6)}';
