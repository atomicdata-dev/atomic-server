import 'package:atomic_chat/atomic_chat.dart' show ToastPalette;
import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the Sync chips use the toast accent hues, light and dark', () {
    for (final (colors, palette) in [
      (AppColors.light, ToastPalette.light),
      (AppColors.dark, ToastPalette.dark),
    ]) {
      expect(SyncTone.info.color(colors), palette.info);
      expect(SyncTone.success.color(colors), palette.success);
      expect(SyncTone.warning.color(colors), palette.warning);
      expect(SyncTone.error.color(colors), palette.error);
    }
  });
}
