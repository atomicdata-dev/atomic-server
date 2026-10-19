import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'atomic_auth.dart';
import 'atomic_client.dart';

/// What the person's managed account says about one workspace: the address it
/// belongs to, and whether Cloud Vault (encrypted backup) and Cloud Server
/// (a hosted, readable copy) are on for it.
class AccountSummary {
  const AccountSummary({
    required this.address,
    required this.portal,
    this.vault,
    this.server,
  });

  final String address;
  final Uri portal;

  /// The drive's Cloud Vault enrollment as the control plane reports it, or
  /// null when it is off (or could not be read).
  final Map<String, dynamic>? vault;

  /// The drive's Cloud Server enrollment, null when off.
  final Map<String, dynamic>? server;
}

/// The linked account's session. It is a bearer token or cookie for one portal, so it
/// lives in platform secure storage like the agent secret, never in prefs.
class AccountStore {
  static const _key = 'atomic_account_session';
  static const _secure = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static Future<void> save(String session) =>
      _secure.write(key: _key, value: session);

  static Future<void> clear() => _secure.delete(key: _key);

  /// The saved session, for a client to restore; null when no account is
  /// linked.
  static Future<String?> read() => _secure.read(key: _key);

  /// The portal agents sign in to when no portal is linked yet.
  static const defaultPortal = 'https://atomic.place';

  static String? _attemptedAgent;

  /// Signs the account in with the active agent when nothing is saved, the way
  /// the web app does, so an agent that is an account identity needs no link
  /// code. True when a session is now saved. Silent otherwise: no account, no
  /// agent or no network all leave things as they were, and a network failure
  /// is tried again on the next start.
  static Future<bool> signInWithAgent({String portal = defaultPortal}) async {
    try {
      if (await read() != null) return true;
      final info = await AtomicClient.getActiveAgent();
      if (info == null || _attemptedAgent == info.subject) return false;
      final agent = AtomicAgent.fromSecret(info.secret);
      final client = shared.AtomicAccountClient(portal);
      try {
        final signedIn = await client.signInWithAgent(agent.subject,
            (message) async => signMessage(message, agent.privateKeyB64));
        // A refusal is final for this run; an unreachable portal throws below.
        _attemptedAgent = info.subject;
        if (!signedIn) return false;
        await save(client.exportSession());
        return true;
      } finally {
        client.close();
      }
    } catch (_) {
      return false;
    }
  }

  /// The linked account's state for [drive]; null when no account is linked.
  /// Throws when it is linked but the portal cannot be read, so a failed read
  /// is not shown as "not linked".
  static Future<AccountSummary?> summary(String? drive) async {
    final saved = await _secure.read(key: _key);
    if (saved == null) return null;
    final origin = shared.AtomicAccountClient.sessionOrigin(saved);
    final client = shared.AtomicAccountClient(origin.toString())
      ..restoreSession(saved);
    try {
      final me = await client.account();
      Future<Map<String, dynamic>?> forDrive(
          Future<List<Map<String, dynamic>>> list) async {
        try {
          final all = await list;
          return all
              .where((e) => e['drive_subject'] == drive)
              .where((e) => e['status'] != 'Disabled')
              .firstOrNull;
        } catch (_) {
          return null;
        }
      }

      return AccountSummary(
        address: (me['address'] ?? me['email']) as String,
        portal: origin,
        vault: await forDrive(client.vaultDrives()),
        server: await forDrive(client.enrollments()),
      );
    } finally {
      client.close();
    }
  }
}
