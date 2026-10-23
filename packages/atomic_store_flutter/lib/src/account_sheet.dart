import 'dart:async';

import 'package:atomic_store/atomic_store.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'atomic_flutter.dart';
import 'drives.dart';
import 'identity.dart';
import 'pairing.dart';
import 'sharing.dart';

/// An icon button for an `AppBar` that opens [showAtomicAccountSheet].
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
        onPressed: () => showAtomicAccountSheet(context, node),
      );
}

/// Opens the account sheet: your name, your drives, sign in, your secret,
/// sharing the drive, adding a device and signing out.
///
/// The secret of the account you were signed in as before a sign-in is kept
/// by the node's `AgentSecretStore`; [onPreviousSecret] also gets it, if the
/// app wants to keep it elsewhere.
Future<void> showAtomicAccountSheet(BuildContext context, AtomicParts node,
        {void Function(String secret)? onPreviousSecret}) =>
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      showDragHandle: true,
      builder: (_) => _AccountSheet(node, onPreviousSecret),
    );

class _AccountSheet extends StatefulWidget {
  const _AccountSheet(this.node, this.onPreviousSecret);

  final AtomicParts node;
  final void Function(String secret)? onPreviousSecret;

  @override
  State<_AccountSheet> createState() => _AccountSheetState();
}

class _AccountSheetState extends State<_AccountSheet> {
  AtomicParts get node => widget.node;

  final _secretField = TextEditingController();
  final _codeField = TextEditingController();
  final _notes = <String, String>{};
  String _name = '';
  List<DriveInfo> _drives = const [];
  bool _signedOut = false;
  bool _showSecret = false;
  bool _write = false;
  String? _link;
  StreamSubscription<Profile>? _profileChanges;

  @override
  void initState() {
    super.initState();
    _load();
    _follow();
  }

  /// Follows the profile of the agent signed in now, so a name changed on
  /// another device shows here without a button. Call again after the agent
  /// changes.
  void _follow() {
    _profileChanges?.cancel();
    _profileChanges = _signedOut
        ? null
        : node.identity.watchProfile().listen((profile) {
            if (mounted && !_signedOut && profile.name != _name) {
              setState(() => _name = profile.name);
            }
          }, onError: (Object _) {});
  }

  @override
  void dispose() {
    _profileChanges?.cancel();
    _secretField.dispose();
    _codeField.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      _name = (await node.identity.profile()).name;
    } on StoreException {
      _name = '';
    }
    _drives = _signedOut ? const [] : await node.drives.list();
    _link = null;
    if (mounted) setState(() {});
  }

  /// Runs [run], and shows its error as the note of [section].
  Future<void> _try(String section, Future<String?> Function() run) async {
    String? note;
    try {
      note = await run();
    } on StoreException catch (e) {
      note = e.message;
    } on FormatException catch (e) {
      note = e.message;
    }
    if (mounted) setState(() => _notes[section] = note ?? '');
  }

  Future<String?> _ask(String title, String initial, String action) =>
      showDialog<String>(
        context: context,
        builder: (context) {
          final field = TextEditingController(text: initial);
          return AlertDialog(
            title: Text(title),
            content: TextField(controller: field, autofocus: true),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancel')),
              FilledButton(
                  onPressed: () => Navigator.pop(context, field.text.trim()),
                  child: Text(action)),
            ],
          );
        },
      );

  String _list(List<String> names) {
    final quoted = [for (final n in names) '"$n"'];
    return quoted.length < 2
        ? quoted.join()
        : '${quoted.sublist(0, quoted.length - 1).join(', ')} and ${quoted.last}';
  }

  Future<void> _signIn() => _try('signIn', () async {
        final found = await node.identity.signIn(_secretField.text.trim());
        final previous = found.previousSecret;
        if (previous != null) widget.onPreviousSecret?.call(previous);
        _secretField.clear();
        _signedOut = false;
        _follow();
        await _load();
        final names = [
          for (final subject in found.broughtAlong)
            _drives
                    .where((d) => d.subject == subject)
                    .map((d) => d.name)
                    .firstOrNull ??
                'Untitled drive'
        ];
        return [
          'You are signed in.',
          if (names.isNotEmpty) 'Added to your account: ${_list(names)}.',
          if (found.needsSync)
            'Your drive is not on this device yet. Connect to a server or add a device to get it.',
        ].join(' ');
      });

  Future<void> _signOut() async {
    final sure = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Sign out?'),
        content: const Text(
            'Your data stays on this device, but you can only get back in with your secret. Copy it first if you have not.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Sign out')),
        ],
      ),
    );
    if (sure != true) return;
    await node.identity.signOut();
    _signedOut = true;
    _showSecret = false;
    _follow();
    await _load();
  }

  Future<void> _copy(String section, String text) async {
    await Clipboard.setData(ClipboardData(text: text));
    if (mounted) setState(() => _notes[section] = 'Copied.');
  }

  Widget _note(String section) => (_notes[section] ?? '').isEmpty
      ? const SizedBox.shrink()
      : Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(_notes[section]!),
        );

  Widget _section(String title, List<Widget> children,
          {void Function(bool)? onExpand}) =>
      ExpansionTile(
        title: Text(title),
        onExpansionChanged: onExpand,
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        expandedCrossAxisAlignment: CrossAxisAlignment.start,
        children: children,
      );

  @override
  Widget build(BuildContext context) {
    final origin = node.sync.status.connected ? node.sync.status.origin : null;
    final secret = node.identity.secret;
    final drive = node.store.drive;
    final theme = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.only(bottom: 24),
      children: [
        ListTile(
          leading: const CircleAvatar(child: Icon(Icons.person)),
          title: Text(_signedOut
              ? 'Signed out'
              : _name.isEmpty
                  ? 'No name yet'
                  : _name),
          subtitle: Text(_signedOut
              ? 'Sign in below to continue.'
              : origin != null
                  ? 'Signed in to your account on $origin'
                  : 'Only on this device'),
          trailing: _signedOut
              ? null
              : IconButton(
                  icon: const Icon(Icons.edit_outlined),
                  tooltip: 'Change name',
                  onPressed: () async {
                    final name = await _ask('Your name', _name, 'Save');
                    if (name == null) return;
                    await _try('name', () async {
                      await node.identity.updateProfile(name: name);
                      await _load();
                      return null;
                    });
                  },
                ),
        ),
        _note('name'),
        if (!_signedOut) ...[
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Text('Your drives', style: theme.textTheme.titleSmall),
          ),
          for (final d in _drives)
            ListTile(
              leading: Icon(d.active
                  ? Icons.radio_button_checked
                  : Icons.radio_button_unchecked),
              title: Text(d.name),
              subtitle: d.unreadable ? const Text('Not available') : null,
              onTap: d.active
                  ? null
                  : () => _try('drives', () async {
                        await node.drives.switchTo(d.subject);
                        await _load();
                        return null;
                      }),
            ),
          ListTile(
            leading: const Icon(Icons.add),
            title: const Text('New drive'),
            onTap: () async {
              final name = await _ask('Name of the new drive', '', 'Create');
              if (name == null || name.isEmpty) return;
              await _try('drives', () async {
                await node.drives.create(name);
                await _load();
                return null;
              });
            },
          ),
          _note('drives'),
        ],
        _section('Sign in', [
          const Text(
              'Paste the secret of your account. What you made on this device is added to it.'),
          const SizedBox(height: 8),
          TextField(
            controller: _secretField,
            decoration: const InputDecoration(labelText: 'Secret'),
            obscureText: true,
          ),
          const SizedBox(height: 8),
          FilledButton(onPressed: _signIn, child: const Text('Sign in')),
          _note('signIn'),
        ]),
        if (!_signedOut && secret != null)
          _section('Your secret', [
            const Text(
                'This is the key to your account. Anyone who has it can be you, so keep it private.'),
            const SizedBox(height: 8),
            if (_showSecret) SelectableText(secret),
            Wrap(spacing: 8, children: [
              OutlinedButton(
                  onPressed: () => setState(() => _showSecret = !_showSecret),
                  child: Text(_showSecret ? 'Hide' : 'Show')),
              OutlinedButton(
                  onPressed: () => _copy('secret', secret),
                  child: const Text('Copy')),
            ]),
            _note('secret'),
          ]),
        if (!_signedOut)
          _section('Share this drive', [
            if (origin == null || drive == null)
              const Text(
                  'Sharing needs a server, and this app is not connected to one.')
            else ...[
              SegmentedButton<bool>(
                segments: const [
                  ButtonSegment(value: false, label: Text('Can read')),
                  ButtonSegment(value: true, label: Text('Can edit')),
                ],
                selected: {_write},
                onSelectionChanged: (s) => setState(() {
                  _write = s.first;
                  _link = null;
                }),
              ),
              const SizedBox(height: 8),
              FilledButton(
                onPressed: () => _try('share', () async {
                  _link = node.sharing.inviteLink(origin, drive,
                      role: _write ? ShareRole.write : ShareRole.read);
                  await Clipboard.setData(ClipboardData(text: _link!));
                  return 'Link copied. Anyone you send it to can open this drive.';
                }),
                child: const Text('Copy invite link'),
              ),
              if (_link != null) ...[
                const SizedBox(height: 8),
                SelectableText(_link!),
              ],
            ],
            _note('share'),
          ]),
        if (!_signedOut)
          _section('Add a device', [
            const Text(
                'Type this code on your other device, or scan it, to sync without a server.'),
            const SizedBox(height: 8),
            if (node.peers.pairingCode != null) ...[
              SelectableText(node.peers.pairingCode!),
              TextButton(
                  onPressed: () => _copy('pair', node.peers.pairingCode!),
                  child: const Text('Copy code')),
            ],
            TextField(
              controller: _codeField,
              decoration:
                  const InputDecoration(labelText: 'Code from another device'),
            ),
            const SizedBox(height: 8),
            FilledButton(
              onPressed: () => _try('pair', () async {
                final code = PairingCode.parse(_codeField.text);
                if (code == null) {
                  return 'That is not a code from another device.';
                }
                final r = await node.peers.pair(_codeField.text);
                _codeField.clear();
                return r.inSync
                    ? 'Device added. Everything was already in sync.'
                    : 'Device added. Received ${r.imported} and sent ${r.pushed} items.';
              }),
              child: const Text('Add device'),
            ),
            _note('pair'),
          ], onExpand: (open) {
            if (open) {
              _try('pair', () async {
                await node.peers.start();
                return null;
              });
            }
          }),
        if (!_signedOut)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
            child: Align(
              alignment: Alignment.centerLeft,
              child: TextButton(
                  onPressed: _signOut, child: const Text('Sign out')),
            ),
          ),
      ],
    );
  }
}
