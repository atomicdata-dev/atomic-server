import 'package:atomic_app/atomic/sync_notice_policy.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late DateTime now;
  late List<DateTime> persisted;
  SyncNoticePolicy make({DateTime? lastShown}) {
    now = DateTime(2026, 1, 1, 12);
    persisted = [];
    return SyncNoticePolicy(
        now: () => now, lastShown: lastShown, onShown: persisted.add);
  }

  void fail(SyncNoticePolicy p, int n, List<bool> out, {bool fg = true}) {
    for (var i = 0; i < n; i++) {
      out.add(p.failed(inForeground: fg));
    }
  }

  test('no notice on the first failures', () {
    final p = make();
    now = now.add(const Duration(minutes: 30));
    final out = <bool>[];
    fail(p, 2, out);
    expect(out, [false, false]);
  });

  test('no notice before the 10 minute mark, one at the threshold', () {
    final p = make();
    final out = <bool>[];
    now = now.add(const Duration(minutes: 9));
    fail(p, 5, out);
    expect(out.any((e) => e), isFalse);
    now = now.add(const Duration(minutes: 1));
    expect(p.failed(inForeground: true), isTrue);
    expect(persisted, [now]);
  });

  test('only once per session', () {
    final p = make();
    now = now.add(const Duration(minutes: 11));
    final out = <bool>[];
    fail(p, 3, out);
    expect(out, [false, false, true]);
    now = now.add(const Duration(hours: 12));
    expect(p.failed(inForeground: true), isFalse);
  });

  test('persisted cool-down blocks the next session', () {
    final p = make(lastShown: DateTime(2026, 1, 1, 8));
    now = now.add(const Duration(minutes: 11));
    final out = <bool>[];
    fail(p, 4, out);
    expect(out.any((e) => e), isFalse);

    final later = make(lastShown: DateTime(2026, 1, 1, 5));
    now = now.add(const Duration(minutes: 11));
    fail(later, 3, out);
    expect(out.last, isTrue);
  });

  test('success clears the streak and the clock', () {
    final p = make();
    now = now.add(const Duration(minutes: 11));
    final out = <bool>[];
    fail(p, 2, out);
    p.succeeded();
    fail(p, 2, out);
    now = now.add(const Duration(minutes: 5));
    fail(p, 1, out);
    expect(out.any((e) => e), isFalse);
    now = now.add(const Duration(minutes: 6));
    expect(p.failed(inForeground: true), isTrue);
  });

  test('never in the background', () {
    final p = make();
    now = now.add(const Duration(minutes: 30));
    final out = <bool>[];
    fail(p, 5, out, fg: false);
    expect(out.any((e) => e), isFalse);
    expect(p.failed(inForeground: true), isTrue);
  });
}
