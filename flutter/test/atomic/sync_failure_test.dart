import 'package:flutter_test/flutter_test.dart';
import 'package:atomic_app/atomic/sync_failure.dart';

void main() {
  test('takes the host summary as the summary and the rest as details', () {
    final f = SyncFailure.parse(
        'No other device answered. Open the app on a device that has your '
        'drive and keep it on the same network.\n'
        '4 devices announced your drive; none answered\n'
        'a9dd56e296f0: Iroh connect timed out after 20s');
    expect(f.summary, startsWith('No other device answered.'));
    expect(f.details, hasLength(2));
    expect(f.details.first, contains('4 devices'));
  });

  test('old joined text: friendly summary, raw text only in details', () {
    final f = SyncFailure.parse(
        'https://staging.atomicdata.dev: ClientConnection closed\n'
        'https://node1.atomicserver.eu: PanicException(Could not determine the '
        'CryptoProvider)\n'
        'None of the 4 devices that announced your drive answered (x)');
    expect(f.summary, startsWith('No other device answered.'));
    expect(f.summary, isNot(contains('://')));
    expect(f.details.any((l) => l.contains('CryptoProvider')), isTrue);
  });

  test('a panic alone gets a generic summary', () {
    final f = SyncFailure.parse('PanicException(boom)');
    expect(f.summary, contains('Something went wrong'));
    expect(f.details, ['PanicException(boom)']);
  });
}
