import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('formatBytes: B, KB, MB, GB', () {
    expect(formatBytes(0), '0 B');
    expect(formatBytes(999), '999 B');
    expect(formatBytes(1536), '1.5 KB');
    expect(formatBytes(1024 * 1024 + 200 * 1024), '1.2 MB');
    expect(formatBytes(15 * 1024 * 1024), '15 MB');
    expect(formatBytes(3 * 1024 * 1024 * 1024), '3.0 GB');
  });

  test('formatCount: exact below 1000, compact above, never "1000k"', () {
    expect(formatCount(0), '0');
    expect(formatCount(842), '842');
    expect(formatCount(1000), '1k');
    expect(formatCount(1234), '1.2k');
    expect(formatCount(15000), '15k');
    expect(formatCount(999999), '1M');
    expect(formatCount(3400000), '3.4M');
  });

  test('formatResources pluralises', () {
    expect(formatResources(1), '1 resource');
    expect(formatResources(1500), '1.5k resources');
  });

  test('StoreStats reads the bridge JSON, biggest drive first', () {
    final s = StoreStats.fromJson({
      'resources': 30,
      'loro_bytes': 2000,
      'blob_bytes': 500,
      'disk_bytes': 9000,
      'drives': [
        {'subject': 'b', 'name': 'Small', 'resources': 5, 'bytes': 100},
        {'subject': 'a', 'name': 'Big', 'resources': 25, 'bytes': 2400},
        {'subject': 'c', 'name': 'Tie', 'resources': 1, 'bytes': 100},
      ],
    })!;
    expect(s.drives.map((d) => d.name), ['Big', 'Small', 'Tie']);
    expect(s.dataBytes, 2500);
    expect(s.diskBytes, 9000);
    expect(s.barTotal, 2600);
  });

  test('StoreStats: no disk size when the host cannot say; junk is null', () {
    expect(StoreStats.fromJson({'drives': []})!.diskBytes, isNull);
    expect(StoreStats.fromJson('nope'), isNull);
  });

  test('shortId keeps short ids and shortens long ones', () {
    expect(shortId('abc'), 'abc');
    expect(shortId('did:ad:agent:0123456789abcdef0123456789abcdef'),
        'did:ad:agent…abcdef');
  });
}
