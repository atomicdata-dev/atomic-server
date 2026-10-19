import 'package:atomiccanvas_flutter/atomic/session.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('only a drive that can be found again from its subject is remembered',
      () async {
    SharedPreferences.setMockInitialValues({});
    await AtomicSession.saveDrive('https://atomicdata.dev/drive/yf0pzh8v8f');
    expect((await SharedPreferences.getInstance()).getString('atomic_drive'),
        isNull);
    await AtomicSession.saveDrive('did:ad:abc');
    expect((await SharedPreferences.getInstance()).getString('atomic_drive'),
        'did:ad:abc');
  });

  test('a legacy drive saved earlier is not used as the resume hint', () {
    expect(AtomicSession.isResumableDrive('https://atomicdata.dev/drive/x'),
        isFalse);
    expect(AtomicSession.isResumableDrive(null), isFalse);
    expect(AtomicSession.isResumableDrive('atomic:abc'), isTrue);
  });
}
