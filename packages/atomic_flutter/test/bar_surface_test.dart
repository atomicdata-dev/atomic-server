import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('barSurface sits above the page and leans towards the main colour', () {
    for (final c in [AppColors.dark, AppColors.light]) {
      final bar = c.barSurface;
      expect(bar, isNot(c.bgBody));
      // Bluer than the page background it is drawn on.
      expect(bar.b - bar.r, greaterThan(c.bgBody.b - c.bgBody.r));
    }
    // Dark: lighter than the pitch-black page, still dark.
    expect(AppColors.dark.barSurface.computeLuminance(),
        inInclusiveRange(0.005, 0.05));
    // Light: still an off-white.
    expect(AppColors.light.barSurface.computeLuminance(), greaterThan(0.85));
  });
}
