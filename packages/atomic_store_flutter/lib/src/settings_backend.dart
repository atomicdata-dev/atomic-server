import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart' as ui;
import 'package:atomic_store/atomic_store.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'atomic_flutter.dart';
import 'drives.dart';
import 'identity.dart';
import 'pairing.dart';
import 'peers.dart';
import 'sharing.dart';

/// An icon button for an `AppBar` that opens the user panel of [node]: name,
/// workspaces, secret, sign in, invite link, devices and sign out.
///
/// ```dart
/// AppBar(title: Text('Notes'), actions: [AtomicAccountButton(node: node)])
/// ```
class AtomicAccountButton extends StatelessWidget {
  const AtomicAccountButton({super.key, required this.node});

  final AtomicParts node;

  @override
  Widget build(BuildContext context) => IconButton(
        icon: const Icon(Icons.account_circle_outlined),
        tooltip: 'Account',
        onPressed: () =>
            ui.showAtomicUserDialog(context, backend: AtomicNodeSettings(node)),
      );
}

/// The shared user panel (`package:atomic_flutter`) over a node: who you are,
/// the workspaces, the paired devices, sign in with a secret, an invite link
/// and sign out.
///
/// The secret of the account you were signed in as before a sign-in is kept
/// by the node's `AgentSecretStore`; [onPreviousSecret] also gets it, if the
/// app wants to keep it elsewhere.
class AtomicNodeSettings extends ui.AtomicSettingsBackend {
  AtomicNodeSettings(this.node, {this.onPreviousSecret});

  final AtomicParts node;
  final void Function(String secret)? onPreviousSecret;
  List<DriveInfo> _drives = const [];

  Identity get _identity => node.identity;

  ui.AtomicIdentity _agent(Profile p) => ui.AtomicIdentity(
      subject: p.subject,
      name: p.name,
      description: p.description,
      emoji: p.emoji,
      imageUrl: p.imageUrl);

  @override
  Future<ui.AtomicIdentity?> getActiveAgent() async {
    final subject = _identity.subject;
    if (subject == null) return null;
    try {
      return _agent(await _identity.profile());
    } on StoreException {
      return ui.AtomicIdentity(subject: subject);
    }
  }

  @override
  Stream<ui.AtomicIdentity?>? watchActiveAgent() =>
      _identity.subject == null ? null : _identity.watchProfile().map(_agent);

  @override
  Future<void> Function(
      {required String name,
      required String description,
      ui.ProfilePicture? picture,
      bool? removePicture})? get saveProfile => (
          {required name, required description, picture, removePicture}) =>
      _identity.updateProfile(name: name, description: description);

  @override
  Future<String> exportSecret() async =>
      _identity.secret ?? (throw StateError('You are signed out.'));

  @override
  Future<List<String>> listDrives() async {
    _drives = _identity.subject == null ? const [] : await node.drives.list();
    return [for (final d in _drives) d.subject];
  }

  @override
  String? getActiveDrive() => node.store.drive;

  @override
  Future<String> getDriveName(String drive) async =>
      _drives.where((d) => d.subject == drive).firstOrNull?.name ?? '';

  @override
  Future<void> createDrive(String name) => node.drives.create(name);

  @override
  Future<void> switchDrive(String drive) => node.drives.switchTo(drive);

  @override
  Future<String?> getPeerId() async => node.peers.nodeId;

  @override
  Future<String> getDeviceName() async => node.peers.deviceName;

  @override
  Future<void> setDeviceName(String name) async => node.peers.deviceName = name;

  @override
  Future<List<Map<String, String>>> getKnownPeers() async => [
        for (final p in node.peers.known) {'node_id': p.nodeId, 'name': p.name}
      ];

  @override
  Future<Set<String>> livePeerIds() async => node.peers.liveIds;

  @override
  Future<List<Map<String, String>>> liveUnsavedPeers() async => [
        for (final p in node.peers.livePeers)
          {'node_id': p.nodeId, 'name': p.name}
      ];

  @override
  Future<void> removeKnownPeer(String nodeId) async =>
      node.peers.remove(nodeId);

  @override
  Future<void> pair(BuildContext context) => showDialog<void>(
      context: context, builder: (_) => _PairDialog(node.peers));

  @override
  Future<String> Function(String nodeId)? get syncPeer => (nodeId) async {
        final r = await node.peers.syncWith(nodeId);
        return _synced(r);
      };

  @override
  void Function()? get searchAgain => node.peers.searchAgain;

  @override
  Future<void> Function()? get signOut => _identity.signOut;

  @override
  Future<String> Function(String secret)? get signInWithSecret =>
      (secret) async {
        final found = await _identity.signIn(secret);
        final previous = found.previousSecret;
        if (previous != null) onPreviousSecret?.call(previous);
        final drives = await node.drives.list();
        final names = [
          for (final subject in found.broughtAlong)
            '"${drives.where((d) => d.subject == subject).map((d) => d.name).firstOrNull ?? 'Untitled drive'}"'
        ];
        return [
          'You are signed in.',
          if (names.isNotEmpty)
            'Added to your account: ${names.length < 2 ? names.join() : '${names.sublist(0, names.length - 1).join(', ')} and ${names.last}'}.',
          if (found.needsSync)
            'Your drive is not on this device yet. Connect to a server or add a device to get it.',
        ].join(' ');
      };

  @override
  Future<String> Function({required bool canEdit})? get inviteLink =>
      ({required canEdit}) async {
        final status = node.sync.status;
        final drive = node.store.drive;
        if (!status.connected || status.origin == null || drive == null) {
          throw StateError(
              'Sharing needs a server, and this app is not connected to one.');
        }
        return node.sharing.inviteLink(status.origin!, drive,
            role: canEdit ? ShareRole.write : ShareRole.read);
      };
}

String _synced(PeerSyncResult r) => r.inSync
    ? 'Everything was already in sync.'
    : 'Received ${r.imported} and sent ${r.pushed} items.';

/// Adding a device: the code to type on the other one, or the other one's.
class _PairDialog extends StatefulWidget {
  const _PairDialog(this.peers);

  final Peers peers;

  @override
  State<_PairDialog> createState() => _PairDialogState();
}

class _PairDialogState extends State<_PairDialog> {
  final _field = TextEditingController();
  String? _note;

  @override
  void initState() {
    super.initState();
    widget.peers.start().then((_) {
      if (mounted) setState(() {});
    }, onError: (Object e) {
      if (mounted) setState(() => _note = '$e');
    });
  }

  @override
  void dispose() {
    _field.dispose();
    super.dispose();
  }

  Future<void> _add() async {
    String note;
    try {
      if (PairingCode.parse(_field.text) == null) {
        throw const FormatException('That is not a code from another device.');
      }
      note = 'Device added. ${_synced(await widget.peers.pair(_field.text))}';
      _field.clear();
    } on FormatException catch (e) {
      note = e.message;
    } on StoreException catch (e) {
      note = e.message;
    }
    if (mounted) setState(() => _note = note);
  }

  @override
  Widget build(BuildContext context) {
    final code = widget.peers.pairingCode;
    return AlertDialog(
      title: const Text('Add a device'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
                'Type this code on your other device, or scan it, to sync without a server.'),
            if (code != null) ...[
              const SizedBox(height: 8),
              SelectableText(code),
              TextButton(
                  onPressed: () => Clipboard.setData(ClipboardData(text: code)),
                  child: const Text('Copy code')),
            ],
            TextField(
              controller: _field,
              decoration:
                  const InputDecoration(labelText: 'Code from another device'),
            ),
            if (_note != null)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(_note!),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close')),
        FilledButton(onPressed: _add, child: const Text('Add device')),
      ],
    );
  }
}
