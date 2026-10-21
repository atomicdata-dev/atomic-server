import 'package:atomic_app/screens/scanner_frame.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Future<Size> frame(WidgetTester tester, Size screen, Size? camera) async {
  tester.view.physicalSize = screen;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: SingleChildScrollView(
        child: ScannerFrame(
          cameraSize: camera,
          onTorch: () {},
          onFlip: () {},
          child: const SizedBox.expand(),
        ),
      ),
    ),
  ));
  return tester.getSize(find.byKey(const Key('scanner-frame')));
}

void main() {
  testWidgets('portrait phone: a portrait preview inside the gutters',
      (tester) async {
    // A sensor reports 1280x720; the preview is turned to the screen.
    final size =
        await frame(tester, const Size(393, 852), const Size(1280, 720));
    expect(size.width / size.height, lessThanOrEqualTo(1));
    expect(size.width / size.height, closeTo(720 / 1280, 0.01));
    expect(size.width, lessThanOrEqualTo(393 - 32));
    expect(size.height, lessThanOrEqualTo(852 * 0.65 + 0.5));
  });

  testWidgets('without a known camera size it is 3:4 portrait', (tester) async {
    final size = await frame(tester, const Size(393, 852), null);
    expect(size.width / size.height, closeTo(3 / 4, 0.01));
    expect(size.width, closeTo(393 - 32, 1));
  });

  testWidgets('landscape: the preview is wide', (tester) async {
    final size =
        await frame(tester, const Size(852, 393), const Size(720, 1280));
    expect(size.width / size.height, greaterThan(1));
    expect(size.height, lessThanOrEqualTo(393 * 0.65 + 0.5));
  });

  testWidgets('tablet: at most 520 wide', (tester) async {
    final size =
        await frame(tester, const Size(800, 1280), const Size(1280, 960));
    expect(size.width, lessThanOrEqualTo(520));
    expect(size.width / size.height, closeTo(3 / 4, 0.01));
  });

  testWidgets('torch and camera switch stay inside the frame and tappable',
      (tester) async {
    await frame(tester, const Size(393, 852), const Size(1280, 720));
    final box = tester.getRect(find.byKey(const Key('scanner-frame')));
    for (final tip in ['Torch', 'Switch camera']) {
      final r = tester.getRect(find.byTooltip(tip));
      expect(box.contains(r.center), isTrue, reason: tip);
      expect(r.width, greaterThanOrEqualTo(48));
    }
  });
}
