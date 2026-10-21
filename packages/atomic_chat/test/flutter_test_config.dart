import 'dart:async';
import 'dart:ui';

import 'package:atomic_chat/atomic_chat.dart' show HomeLayout;
import 'package:flutter_test/flutter_test.dart';

/// Every test runs on a phone (393 x 851, as a Pixel), unless it sets its own
/// size: the test default of 800 x 600 is wide enough for the shell's tablet
/// layout ([ShellLayout.split]), and these tests are about the phone's.
/// The tablet layouts have their own tests (`tablet_layout_test.dart`).
Future<void> testExecutable(FutureOr<void> Function() testMain) async {
  setUp(() {
    // The panels start closed in the app; most tests are about their rows,
    // so they start open and without the compact accordion. The panel tests
    // say otherwise.
    HomeLayout.fresh = const HomeLayout();
    HomeLayout.accordionOverride = false;
    final view = TestWidgetsFlutterBinding.ensureInitialized()
        .platformDispatcher
        .views
        .first;
    view.physicalSize = const Size(1080, 2340);
    view.devicePixelRatio = 1080 / 393;
  });
  await testMain();
}
