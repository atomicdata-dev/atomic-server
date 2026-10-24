import 'package:atomic_store_flutter/atomic_store_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('MemoryAgentSecrets keeps, forgets and archives', () async {
    final s = MemoryAgentSecrets();
    expect(await s.read('k'), isNull);
    await s.write('k', 'one');
    expect(await s.read('k'), 'one');
    await s.archive('k', 'old1');
    await s.archive('k', 'old2');
    expect(s.values['k.old'], 'old1\nold2');
    await s.delete('k');
    expect(await s.read('k'), isNull);
  });

  test('secret key depends on the path only without a keychain group', () {
    expect(AtomicFlutter.agentSecretKey('/a'), 'atomic_agent:/a');
    expect(AtomicFlutter.agentSecretKey('/a', keychainGroup: 'g'),
        AtomicFlutter.agentSecretKey('/b', keychainGroup: 'g'));
    expect(AtomicFlutter.agentSecretKey('/a', keychainGroup: 'g'),
        isNot(AtomicFlutter.agentSecretKey('/a')));
  });

  test('keychainGroup together with a custom secretStore is refused', () {
    expect(
        () => AtomicFlutter.open(
            path: '/x',
            secretStore: MemoryAgentSecrets(),
            keychainGroup: 'g'),
        throwsArgumentError);
  });
}
