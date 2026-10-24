import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'copyable_error.dart';
import 'device_stats.dart';
import 'error_snack.dart';
import 'server_settings_section.dart';
import 'settings_backend.dart';
import 'sync_widgets.dart';
import 'theme.dart';

/// What the panel knows, for the sections a host adds ([AtomicUserPanel]'s
/// builders).
class AtomicUserInfo {
  const AtomicUserInfo({
    required this.agent,
    required this.deviceName,
    required this.peerId,
    required this.activeDrive,
    required this.driveNames,
    required this.loads,
    required this.rename,
  });

  final AtomicIdentity? agent;
  final String deviceName;

  /// This device's node id, null while it is not online.
  final String? peerId;
  final String? activeDrive;

  /// Workspace names read so far; empty for one not received yet.
  final Map<String, String> driveNames;

  /// How often the panel has loaded: a section reloads what it read when this
  /// changes (a workspace was switched, a server changed).
  final int loads;

  /// Asks for a new device name.
  final VoidCallback rename;

  String driveLabel(String drive) => (driveNames[drive]?.isNotEmpty ?? false)
      ? driveNames[drive]!
      : 'Workspace';
}

/// Who you are and everything that syncs, after the web app's Sync page: your
/// identity, the workspace, this device and the devices and servers it syncs
/// with. The app shows it as a page, other apps as a dialog
/// ([showAtomicUserDialog]).
///
/// It is driven by an [AtomicSettingsBackend]; what the backend cannot do is
/// not shown. The host adds what only it has through the optional hooks.
class AtomicUserPanel extends StatefulWidget {
  const AtomicUserPanel({
    super.key,
    required this.backend,
    this.avatarBuilder,
    this.openProfile,
    this.accountBuilder,
    this.thisDeviceBuilder,
    this.signInAsOther,
    this.onSignedOut,
    this.onCopied,
  });

  final AtomicSettingsBackend backend;

  /// The circle for an identity; its picture, emoji or initial by default.
  final Widget Function(AtomicIdentity? agent, double radius)? avatarBuilder;

  /// The agent's profile page. Without it a backend that can save the profile
  /// gets a dialog for the name.
  final Future<void> Function(BuildContext context, AtomicIdentity agent)?
      openProfile;

  /// The account that hosts the data, between the workspace and this device.
  final Widget Function(BuildContext context, AtomicUserInfo info)?
      accountBuilder;

  /// This device's section; a row with its name by default.
  final Widget Function(BuildContext context, AtomicUserInfo info)?
      thisDeviceBuilder;

  /// Signing in as another account, after the backend's own way of signing in
  /// with a pasted secret. Resolves true when the panel has to reload.
  final Future<bool> Function(BuildContext context)? signInAsOther;

  /// Called after signing out. Without it the panel reloads.
  final VoidCallback? onSignedOut;

  /// Says that something was copied; a SnackBar by default.
  final void Function(BuildContext context, String message)? onCopied;

  @override
  State<AtomicUserPanel> createState() => _AtomicUserPanelState();
}

class _AtomicUserPanelState extends State<AtomicUserPanel> {
  AtomicSettingsBackend get _backend => widget.backend;

  final _secretField = TextEditingController();
  bool _loading = true;
  String? _error;
  AtomicIdentity? _agent;
  String _deviceName = '';
  String? _peerId;
  String? _activeDrive;
  Map<String, String> _drives = {};
  int _loads = 0;
  StreamSubscription<AtomicIdentity?>? _watch;

  String? _revealed;
  bool _signInOpen = false;
  String? _signInNote;
  bool _signInFailed = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _watch?.cancel();
    _secretField.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    List<String> drives = const [];
    try {
      final agent = await _backend.getActiveAgent();
      final deviceName = await _backend.getDeviceName();
      final peerId = await _backend.getPeerId();
      if (!mounted) return;
      // Show the panel now; a person with many drives must not wait for
      // every drive's name before seeing their own devices.
      setState(() {
        _agent = agent;
        _deviceName = deviceName;
        _peerId = peerId;
        _activeDrive = _backend.getActiveDrive();
        _error = null;
        _loading = false;
        _loads++;
      });
      _follow();
      // Listing the drives reads each one, which is slow with many: after the
      // panel is up.
      drives = await _backend.listDrives();
      if (!mounted) return;
      setState(() => _drives = {for (final d in drives) d: _drives[d] ?? ''});
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
          _loading = false;
          _loads++;
        });
      }
    }
    // Names fill in as they arrive, in parallel, each with a deadline.
    await Future.wait([
      for (final d in drives)
        () async {
          try {
            final name = await _backend
                .getDriveName(d)
                .timeout(const Duration(seconds: 5));
            if (mounted) setState(() => _drives[d] = name);
          } catch (_) {}
        }(),
    ]);
  }

  /// Follows the agent, so a name changed on another device shows without a
  /// button. Again after every load: a sign-in is a new agent.
  void _follow() {
    _watch?.cancel();
    _watch = _backend.watchActiveAgent()?.listen((agent) {
      if (mounted) setState(() => _agent = agent);
    }, onError: (Object _) {});
  }

  void _copy(String text, String what) {
    Clipboard.setData(ClipboardData(text: text));
    final onCopied = widget.onCopied;
    if (onCopied != null) return onCopied(context, '$what copied');
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('$what copied')));
  }

  void _fail(String what, Object e) => showErrorSnack(context, '$what: $e');

  Future<String?> _ask(String title, String hint, {String initial = ''}) {
    final controller = TextEditingController(text: initial);
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: InputDecoration(hintText: hint),
          onSubmitted: (v) => Navigator.pop(ctx, v.trim()),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(
              onPressed: () => Navigator.pop(ctx, controller.text.trim()),
              child: const Text('Save')),
        ],
      ),
    );
  }

  Future<void> _rename() async {
    final name =
        await _ask('Device name', 'Only on this device', initial: _deviceName);
    if (name == null || name.isEmpty) return;
    try {
      await _backend.setDeviceName(name);
      if (mounted) setState(() => _deviceName = name);
    } catch (e) {
      if (mounted) _fail('Could not rename the device', e);
    }
  }

  bool get _canEditProfile =>
      widget.openProfile != null || _backend.saveProfile != null;

  Future<void> _openProfile() async {
    final agent = _agent;
    if (agent == null || !_canEditProfile) return;
    final open = widget.openProfile;
    if (open != null) {
      await open(context, agent);
    } else {
      final name = await _ask('Your name', 'Name, seen on all your devices',
          initial: agent.name ?? '');
      if (name == null || name.isEmpty) return;
      try {
        await _backend.saveProfile!(
            name: name, description: agent.description ?? '');
      } catch (e) {
        if (mounted) _fail('Could not save the name', e);
      }
    }
    if (mounted) await _load();
  }

  Future<void> _newWorkspace() async {
    final name = await _ask('New workspace', 'Name');
    if (name == null || name.isEmpty) return;
    try {
      await _backend.createDrive(name);
      await _load();
    } catch (e) {
      if (mounted) _fail('Could not create the workspace', e);
    }
  }

  Future<void> _switch(String drive) async {
    try {
      await _backend.switchDrive(drive);
      await _load();
    } catch (e) {
      if (mounted) _fail('Could not switch workspace', e);
    }
  }

  Future<void> _copySecret() async {
    try {
      _copy(await _backend.exportSecret(), 'Secret key');
    } catch (e) {
      if (mounted) _fail('Could not copy the secret key', e);
    }
  }

  Future<void> _toggleSecret() async {
    if (_revealed != null) return setState(() => _revealed = null);
    try {
      final secret = await _backend.exportSecret();
      if (mounted) setState(() => _revealed = secret);
    } catch (e) {
      if (mounted) _fail('Could not show the secret key', e);
    }
  }

  Future<void> _signInWithSecret() async {
    String note;
    var failed = false;
    try {
      note = await _backend.signInWithSecret!(_secretField.text.trim());
      _secretField.clear();
    } catch (e) {
      note = '$e';
      failed = true;
    }
    if (!mounted) return;
    setState(() {
      _signInNote = note;
      _signInFailed = failed;
      _signInOpen = failed;
      _revealed = null;
    });
    if (!failed) await _load();
  }

  Future<void> _signInAsOther() async {
    if (await widget.signInAsOther!(context) && mounted) await _load();
  }

  Future<void> _signOut() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Sign out?'),
        content: const Text(
            "Your data stays on this device, but you'll need your secret key to sign back in."),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          TextButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Sign out')),
        ],
      ),
    );
    if (confirm != true) return;
    try {
      await _backend.signOut!();
      final done = widget.onSignedOut;
      if (done != null) return done();
      _revealed = null;
      if (mounted) await _load();
    } catch (e) {
      if (mounted) _fail('Could not sign out', e);
    }
  }

  Future<void> _openInvite() async {
    final link = await _ask('Open an invite', 'Paste the invite link');
    if (link == null || link.isEmpty) return;
    try {
      final line = await _backend.openInvite!(link);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(line)));
      await _load();
    } catch (e) {
      if (mounted) _fail('Could not open the invite', e);
    }
  }

  Future<void> _invite() async {
    final link = _backend.inviteLink!;
    await showDialog<void>(
      context: context,
      builder: (ctx) {
        var canEdit = false;
        String? copied;
        String? failed;
        return StatefulBuilder(
          builder: (ctx, setInner) => AlertDialog(
            title: const Text('Invite to this workspace'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SegmentedButton<bool>(
                  segments: const [
                    ButtonSegment(value: false, label: Text('Can read')),
                    ButtonSegment(value: true, label: Text('Can edit')),
                  ],
                  selected: {canEdit},
                  onSelectionChanged: (s) => setInner(() {
                    canEdit = s.first;
                    copied = null;
                  }),
                ),
                if (copied != null) ...[
                  const SizedBox(height: SyncGap.m),
                  SelectableText(copied!),
                  const SizedBox(height: SyncGap.s),
                  Text(copied!.startsWith('atomic:')
                      // No server: the invite is redeemed by this device.
                      ? 'Link copied. Whoever has it can open this workspace '
                          'in their Atomic app, while this device is online.'
                      : 'Link copied. Anyone with it can open this workspace.'),
                ],
                // Inline: this dialog sits above the panel's own messenger.
                if (failed != null) ...[
                  const SizedBox(height: SyncGap.m),
                  ErrorText('Could not make the link: $failed'),
                ],
              ],
            ),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: const Text('Close')),
              TextButton(
                onPressed: () async {
                  try {
                    final url = await link(canEdit: canEdit);
                    await Clipboard.setData(ClipboardData(text: url));
                    if (!ctx.mounted) return;
                    setInner(() {
                      copied = url;
                      failed = null;
                    });
                  } catch (e) {
                    if (ctx.mounted) setInner(() => failed = '$e');
                  }
                },
                child: const Text('Copy invite link'),
              ),
            ],
          ),
        );
      },
    );
  }

  String _driveLabel(String drive) =>
      (_drives[drive]?.isNotEmpty ?? false) ? _drives[drive]! : 'Workspace';

  AtomicUserInfo get _info => AtomicUserInfo(
      agent: _agent,
      deviceName: _deviceName,
      peerId: _peerId,
      activeDrive: _activeDrive,
      driveNames: _drives,
      loads: _loads,
      rename: _rename);

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    final c = syncColors(context);
    final info = _info;
    return ListView(
      padding: const EdgeInsets.fromLTRB(SyncGap.l, SyncGap.xs, SyncGap.l, 32),
      children: [
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(bottom: SyncGap.m),
            child: SyncNote(_error!,
                tone: SyncTone.error, icon: Icons.error_outline),
          ),
        _identity(c),
        if (_backend.signInWithSecret != null) _secrets(c),
        _workspaceSwitcher(c),
        if (widget.accountBuilder != null)
          widget.accountBuilder!(context, info),
        widget.thisDeviceBuilder?.call(context, info) ??
            SyncSection(title: 'This device', children: [
              SyncRow(
                icon: Icons.smartphone,
                title: _deviceName.isEmpty ? 'This device' : _deviceName,
                subtitle: 'Device name, only on this device. Tap to rename.',
                onTap: _rename,
              ),
            ]),
        // Servers, paired devices and the pairing code: the browser's
        // Devices list.
        ServerSettingsSection(backend: _backend, onServerChanged: _load),
      ],
    );
  }

  Widget _avatar(AtomicIdentity? agent, double radius) {
    final custom = widget.avatarBuilder;
    if (custom != null) return custom(agent, radius);
    final bytes = agent?.imageBytes;
    final name = agent?.name ?? '';
    return CircleAvatar(
      radius: radius,
      backgroundImage: bytes == null ? null : MemoryImage(bytes),
      child: bytes != null
          ? null
          : Text(agent?.emoji ??
              (name.isEmpty ? '?' : name.substring(0, 1).toUpperCase())),
    );
  }

  Widget _identity(AppColors c) {
    final agent = _agent;
    final canEdit = agent != null && _canEditProfile;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        InkWell(
          mouseCursor: WidgetStateMouseCursor.clickable,
          onTap: canEdit ? _openProfile : null,
          borderRadius: BorderRadius.circular(12),
          child: Row(children: [
            _avatar(agent, 28),
            const SizedBox(width: SyncGap.l),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    (agent?.name?.isNotEmpty ?? false) ? agent!.name! : 'You',
                    style: SyncText.title(c),
                  ),
                  if (agent != null)
                    // The ID with a copy mark: a bare line of grey text gave
                    // no hint that a tap copies it.
                    Tooltip(
                      message: 'Copy ID',
                      child: InkWell(
                        mouseCursor: WidgetStateMouseCursor.clickable,
                        key: const Key('copy-agent-id'),
                        onTap: () => _copy(agent.subject, 'Agent ID'),
                        borderRadius: BorderRadius.circular(6),
                        child: Padding(
                          padding:
                              const EdgeInsets.symmetric(vertical: SyncGap.s),
                          child: Row(mainAxisSize: MainAxisSize.min, children: [
                            Flexible(
                              child: Text(shortId(agent.subject),
                                  overflow: TextOverflow.ellipsis,
                                  style: SyncText.caption(c)),
                            ),
                            const SizedBox(width: SyncGap.s),
                            Icon(Icons.copy, size: 20, color: c.textSecondary),
                          ]),
                        ),
                      ),
                    ),
                ],
              ),
            ),
            if (canEdit)
              Icon(Icons.chevron_right, size: 24, color: c.textSecondary),
          ]),
        ),
        const SizedBox(height: SyncGap.m),
        Wrap(spacing: SyncGap.s, runSpacing: SyncGap.s, children: [
          if (canEdit)
            SyncActionButton(
              icon: Icons.edit_outlined,
              label: widget.openProfile != null
                  ? 'Edit profile'
                  : 'Edit your name',
              onPressed: _openProfile,
            ),
          if (agent != null)
            SyncActionButton(
              icon: Icons.key,
              label: 'Copy secret key',
              onPressed: _copySecret,
            ),
          if (_backend.signOut != null && widget.signInAsOther != null)
            SyncActionButton(
              icon: Icons.swap_horiz,
              label: 'Sign in to another account',
              onPressed: _signInAsOther,
            ),
          if (_backend.signOut != null && agent != null)
            SyncActionButton(
              icon: Icons.logout,
              label: 'Sign out',
              onPressed: _signOut,
            ),
        ]),
      ],
    );
  }

  /// Showing the secret and signing in with one: a row each, closed until
  /// tapped.
  Widget _secrets(AppColors c) => Padding(
        padding: const EdgeInsets.only(top: SyncGap.l),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SyncCard(divided: true, children: [
            if (_agent != null)
              SyncRow(
                icon: Icons.visibility_outlined,
                title:
                    _revealed == null ? 'Show secret key' : 'Hide secret key',
                onTap: _toggleSecret,
              ),
            if (_revealed != null)
              Padding(
                padding: const EdgeInsets.all(SyncGap.l),
                child: SelectableText(_revealed!, style: SyncText.mono(c)),
              ),
            SyncRow(
              icon: Icons.login,
              title: 'Sign in with a secret key',
              trailing: Icon(
                  _signInOpen ? Icons.expand_less : Icons.expand_more,
                  size: 24,
                  color: c.textSecondary),
              onTap: () => setState(() => _signInOpen = !_signInOpen),
            ),
            if (_signInOpen)
              Padding(
                padding: const EdgeInsets.all(SyncGap.l),
                child: Column(children: [
                  TextField(
                    key: const ValueKey('user-signin-secret'),
                    controller: _secretField,
                    obscureText: true,
                    decoration: const InputDecoration(
                        labelText: 'Secret key',
                        helperText:
                            'What you made on this device is added to it.'),
                  ),
                  const SizedBox(height: SyncGap.m),
                  SyncActionButton(
                    kind: SyncButtonKind.primary,
                    label: 'Sign in',
                    onPressed: _signInWithSecret,
                  ),
                ]),
              ),
          ]),
          if (_signInNote != null)
            Padding(
              padding: const EdgeInsets.only(top: SyncGap.s),
              child: SyncNote(_signInNote!,
                  tone: _signInFailed ? SyncTone.error : SyncTone.success),
            ),
        ]),
      );

  /// One row: the current workspace. It opens a sheet to switch, so the page
  /// is not a list of every workspace.
  Widget _workspaceSwitcher(AppColors c) {
    final active = _activeDrive;
    return Padding(
      padding: const EdgeInsets.only(top: SyncGap.l),
      child: SyncCard(divided: true, children: [
        SyncRow(
          icon: Icons.folder_outlined,
          title: active == null ? 'No workspace' : _driveLabel(active),
          subtitle: 'Workspace',
          trailing: Icon(Icons.expand_more, size: 24, color: c.textSecondary),
          onTap: _pickWorkspace,
        ),
        if (_backend.inviteLink != null && active != null)
          SyncRow(
            icon: Icons.person_add_alt_outlined,
            title: 'Invite someone',
            onTap: _invite,
          ),
        if (_backend.openInvite != null)
          SyncRow(
            icon: Icons.link,
            title: 'Open an invite',
            onTap: _openInvite,
          ),
      ]),
    );
  }

  /// The workspaces that are on this device, each once. Listed drives that
  /// have not been received (no name yet) are one line, not forty.
  Future<void> _pickWorkspace() async {
    String key(String drive) =>
        drive.replaceFirst(RegExp(r'^(did:ad:|atomic:)'), '').split('?').first;
    final seen = <String>{};
    final shown = <String>[];
    var elsewhere = 0;
    for (final d in _drives.keys) {
      if (!seen.add(key(d))) continue;
      final named = (_drives[d] ?? '').isNotEmpty;
      if (named || d == _activeDrive) {
        shown.add(d);
      } else {
        elsewhere++;
      }
    }
    final c = syncColors(context);
    final picked = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      backgroundColor: c.bgBody,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(12))),
      builder: (ctx) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            for (final d in shown)
              SyncRow(
                icon: d == _activeDrive
                    ? Icons.radio_button_checked
                    : Icons.radio_button_off,
                title: _driveLabel(d),
                onTap: () => Navigator.pop(ctx, d),
              ),
            if (elsewhere > 0)
              SyncRow(
                icon: Icons.cloud_download_outlined,
                iconColor: c.textSecondary,
                title:
                    '$elsewhere more workspace${elsewhere == 1 ? '' : 's'} not on this device yet',
              ),
            SyncRow(
              icon: Icons.add,
              title: 'New workspace',
              onTap: () => Navigator.pop(ctx, ''),
            ),
          ],
        ),
      ),
    );
    if (!mounted || picked == null) return;
    if (picked.isEmpty) {
      await _newWorkspace();
    } else if (picked != _activeDrive) {
      await _switch(picked);
    }
  }
}

/// Opens [AtomicUserPanel] over [backend]: a dialog on a wide screen, a full
/// screen page on a narrow one. Takes the panel's hooks like the panel does.
Future<void> showAtomicUserDialog(
  BuildContext context, {
  required AtomicSettingsBackend backend,
  Widget Function(AtomicIdentity? agent, double radius)? avatarBuilder,
  Future<void> Function(BuildContext context, AtomicIdentity agent)?
      openProfile,
}) {
  // Its own messenger: the panel's snacks stay in this route, above its
  // barrier, and never reach the host app's scaffold behind it.
  Widget page(BuildContext ctx) => ScaffoldMessenger(
        child: Scaffold(
          backgroundColor: syncColors(ctx).bgBody,
          appBar: AppBar(
            title: const Text('User'),
            backgroundColor: syncColors(ctx).bgBody,
          ),
          body: AtomicUserPanel(
            backend: backend,
            avatarBuilder: avatarBuilder,
            openProfile: openProfile,
          ),
        ),
      );
  if (MediaQuery.sizeOf(context).width < 700) {
    return Navigator.of(context)
        .push(MaterialPageRoute<void>(fullscreenDialog: true, builder: page));
  }
  return showDialog<void>(
    context: context,
    builder: (ctx) => Dialog(
      clipBehavior: Clip.antiAlias,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560, maxHeight: 760),
        child: page(ctx),
      ),
    ),
  );
}
