import 'dart:io';
import 'package:atomiccanvas_flutter/atomic/atomic_client.dart';
import 'package:atomiccanvas_flutter/atomic/settings_backend.dart';
import 'package:atomiccanvas_flutter/src/rust/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('settings backend reads a native Atomic identity and drive',
      (tester) async {
    await RustLib.init();
    final dir = await Directory.systemTemp.createTemp('atomic-settings-test-');
    addTearDown(() => dir.delete(recursive: true));
    await AtomicClient.openDb(dir.path);
    final account = await AtomicClient.setup('Package test');
    final backend = CanvasSettingsBackend();
    expect((await backend.getActiveAgent())?.subject, account.agentSubject);
    expect(await backend.listDrives(), contains(account.driveSubject));
    expect(await backend.exportSecret(), account.agentSecret);
  });
}
