import 'package:atomic_store_flutter/bridge/api/error.dart' as bridge;
import 'package:atomic_store_flutter/bridge/api/resources.dart' as bridge;

import 'atomic_client.dart';

/// What signing in as another account, while signed in, found.
class AccountSwitch {
  const AccountSwitch(
      {this.same = false, this.broughtAlong = const [], this.previousSecret});

  /// The secret is the account that is signed in already: nothing to do.
  final bool same;

  /// Names of the drives of the account signed in before that the new one
  /// can use now.
  final List<String> broughtAlong;

  /// The secret of the account signed in before, to keep.
  final String? previousSecret;
}

/// Brings the work of the signed-in account along to the account of [secret]
/// (the bridge's `sign_in`, on a handle that signs as the current account and
/// shares the app's store file). The app's own session is switched afterwards,
/// by the usual resume.
Future<AccountSwitch> switchAccountOnDevice(String secret) async {
  final path = AtomicClient.dbPath;
  final current = await AtomicClient.getActiveAgent();
  if (path == null || current == null) return const AccountSwitch();
  final handle =
      await bridge.AtomicStore.open(path: path, agentSecret: current.secret);
  try {
    final found = await handle.signIn(secret: secret);
    return AccountSwitch(
        same: found.agentSubject == current.subject,
        broughtAlong: [
          for (final drive in found.broughtAlong) await _nameOf(drive)
        ],
        previousSecret: found.previousSecret);
  } on bridge.AtomicError catch (e) {
    throw StateError(e.message);
  } finally {
    handle.dispose();
  }
}

Future<String> _nameOf(String drive) async {
  try {
    final name = await AtomicClient.getProperty(
        drive, 'https://atomicdata.dev/properties/name');
    if (name.trim().isNotEmpty) return name.trim();
  } catch (_) {}
  return 'Untitled drive';
}
