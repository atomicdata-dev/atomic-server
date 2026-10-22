import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'atomic_auth.dart';
import 'atomic_client.dart';
import 'session.dart' show createSecureStorage;

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
  static final FlutterSecureStorage _secure = createSecureStorage();

  /// This run's session, for when the Keychain will not keep it.
  static String? _memory;

  /// Saving never throws: an unavailable Keychain only means the link is not
  /// remembered after this run.
  static Future<void> save(String session) async {
    _memory = session;
    try {
      await _secure.write(key: _key, value: session);
    } catch (e) {
      debugPrint('Saving the account session failed: $e');
    }
  }

  static Future<void> clear() async {
    _memory = null;
    try {
      await _secure.delete(key: _key);
    } catch (e) {
      debugPrint('Deleting the account session failed: $e');
    }
  }

  /// The saved session, for a client to restore; null when no account is
  /// linked (or the Keychain is unavailable and nothing is held in memory).
  static Future<String?> read() async {
    try {
      return await _secure.read(key: _key) ?? _memory;
    } catch (e) {
      debugPrint('Reading the account session failed: $e');
      return _memory;
    }
  }

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

  /// The `session_token` cookie that signs a web view in to [portal] as the
  /// active agent, or null when it cannot (no agent, not an account identity,
  /// unreachable). Reuses the saved session when it is a cookie one for this
  /// portal; otherwise does a fresh agent sign-in, because a bearer token from
  /// the link flow cannot become a cookie. Never throws, and never saves the
  /// result as the app's session.
  static Future<String?> portalCookie(Uri portal) async {
    try {
      final origin = shared.AtomicAccountClient.providerOrigin(
          portal.replace(path: '', query: null, fragment: null).toString());
      final saved = await read();
      if (saved != null) {
        try {
          final client = shared.AtomicAccountClient(origin.toString());
          try {
            client.restoreSession(saved);
            final cookie = client.sessionCookie;
            if (cookie != null) return cookie;
          } finally {
            client.close();
          }
        } catch (_) {
          // Another portal or a bearer token: sign in afresh below.
        }
      }
      final info = await AtomicClient.getActiveAgent();
      if (info == null) return null;
      final agent = AtomicAgent.fromSecret(info.secret);
      final client = shared.AtomicAccountClient(origin.toString());
      try {
        final ok = await client.signInWithAgent(agent.subject,
            (message) async => signMessage(message, agent.privateKeyB64));
        return ok ? client.sessionCookie : null;
      } finally {
        client.close();
      }
    } catch (_) {
      return null;
    }
  }

  /// The linked account's AI credits; null when no account is linked or the
  /// portal offers no included AI. Throws when the portal cannot be reached,
  /// so the caller can keep showing the last known balance.
  static Future<shared.AtomicAiCredits?> aiCredits() async {
    final saved = await _secure.read(key: _key);
    if (saved == null) return null;
    final origin = shared.AtomicAccountClient.sessionOrigin(saved);
    final client = shared.AtomicAccountClient(origin.toString())
      ..restoreSession(saved);
    try {
      return await client.aiCredits();
    } finally {
      client.close();
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
