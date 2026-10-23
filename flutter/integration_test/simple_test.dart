import 'dart:io';
import 'package:atomic_app/atomic/atomic_client.dart';
import 'package:atomic_app/atomic/settings_backend.dart';
import 'package:atomic_store_flutter/bridge/frb_generated.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart' show nativeLibrary;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('settings backend reads a native Atomic identity and drive',
      (tester) async {
    await RustLib.init(externalLibrary: nativeLibrary());
    final dir = await Directory.systemTemp.createTemp('atomic-settings-test-');
    addTearDown(() => dir.delete(recursive: true));
    await AtomicClient.openDb(dir.path);
    final account = await AtomicClient.setup('Package test');
    final backend = AppSettingsBackend();
    expect((await backend.getActiveAgent())?.subject, account.agentSubject);
    expect(await backend.listDrives(), contains(account.driveSubject));
    expect(await backend.exportSecret(), account.agentSecret);
  });
}
