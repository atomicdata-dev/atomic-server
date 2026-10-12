import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'settings_backend.dart';
import 'error_snack.dart';
import 'server_settings_section.dart';

class AgentSettingsDialog extends StatefulWidget {
  const AgentSettingsDialog({super.key, required this.backend});

  final AtomicSettingsBackend backend;

  static Future<bool> show(BuildContext context,
      {required AtomicSettingsBackend backend}) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AgentSettingsDialog(backend: backend),
    );
    return result ?? false;
  }

  @override
  State<AgentSettingsDialog> createState() => _AgentSettingsDialogState();
}

class _AgentSettingsDialogState extends State<AgentSettingsDialog> {
  AtomicIdentity? _agent;
  String? _error;
  List<String> _drives = [];
  Map<String, String> _driveNames = {};
  String? _activeDrive;
  bool _loading = true;
  bool _creatingDrive = false;
  bool _showNewDrive = false;
  String? _peerId;
  // The peer never starts from this dialog anymore (pairing is its own screen),
  // but the "This device" card still reads it as an online/starting hint.
  final bool _peerStarting = false;
  String _deviceName = '';
  final _newDriveController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  @override
  void dispose() {
    _newDriveController.dispose();
    super.dispose();
  }

  // ── Actions ──────────────────────────────────────────────────────────

  Future<void> _loadData() async {
    setState(() => _loading = true);
    try {
      final deviceName = await widget.backend.getDeviceName();
      final agent = await widget.backend.getActiveAgent();
      final drives = await widget.backend.listDrives();
      final activeDrive = widget.backend.getActiveDrive();
      final peerId = await widget.backend.getPeerId();

      final names = <String, String>{};
      for (final d in drives) {
        try {
          names[d] = await widget.backend.getDriveName(d);
        } catch (_) {
          names[d] = '';
        }
      }

      if (!mounted) return;
      setState(() {
        _error = null;
        _deviceName = deviceName;
        _agent = agent;
        _drives = drives;
        _driveNames = names;
        _activeDrive = activeDrive;
        _peerId = peerId;
        _loading = false;
      });
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
          _loading = false;
        });
      }
    }
  }

  Future<void> _createDrive() async {
    final name = _newDriveController.text.trim();
    if (name.isEmpty) return;
    setState(() => _creatingDrive = true);
    try {
      await widget.backend.createDrive(name);
      if (!mounted) return;
      _newDriveController.clear();
      setState(() => _showNewDrive = false);
      await _loadData();
    } catch (e) {
      if (mounted) showErrorSnack(context, 'Failed to create drive: $e');
    }
    if (mounted) setState(() => _creatingDrive = false);
  }

  Future<void> _switchDrive(String drive) async {
    try {
      await widget.backend.switchDrive(drive);
      if (!mounted) return;
      setState(() => _activeDrive = drive);
    } catch (e) {
      if (mounted) showErrorSnack(context, 'Failed to switch drive: $e');
    }
  }

  Future<void> _signOut() async {
    final navigator = Navigator.of(context);
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Sign out?'),
        content: const Text(
            'Your local data will be kept, but you\'ll need your secret to sign back in.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('Sign out'),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    try {
      await widget.backend.signOut!();
      if (navigator.mounted) navigator.pop(true);
    } catch (e) {
      if (mounted) showErrorSnack(context, 'Could not sign out: $e');
    }
  }

  void _copyToClipboard(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
          content: Text('$label copied'), duration: const Duration(seconds: 2)),
    );
  }

  // ── Build ────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    final screenWidth = MediaQuery.of(context).size.width;
    final isPhone = screenWidth < 600;
    final dialogWidth = isPhone ? screenWidth * 0.92 : 420.0;

    return AlertDialog(
      title: const Text('Settings'),
      insetPadding: EdgeInsets.symmetric(
        horizontal: isPhone ? 12 : 40,
        vertical: 24,
      ),
      content: _loading
          ? const SizedBox(
              height: 200, child: Center(child: CircularProgressIndicator()))
          : SizedBox(
              width: dialogWidth,
              child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // This device, then the devices it syncs with, then the
                    // code to add another — the same order as the browser Sync
                    // page. A server is one of those devices (an always-on
                    // one), not a category of its own.
                    if (_error != null) ...[
                      Text(_error!,
                          style: TextStyle(color: theme.colorScheme.error)),
                      TextButton(
                          onPressed: _loadData, child: const Text('Retry')),
                    ],
                    if (widget.backend.signInWithAccount != null) ...[
                      Text(widget.backend.accountStatus ??
                          'Connect your Atomic account'),
                      const SizedBox(height: 8),
                      Wrap(spacing: 8, children: [
                        OutlinedButton.icon(
                            icon: const Icon(Icons.account_circle_outlined),
                            label: const Text('Sign in with account'),
                            onPressed: () async {
                              try {
                                await widget
                                    .backend.signInWithAccount!(context);
                                await _loadData();
                              } catch (e) {
                                if (context.mounted) {
                                  showErrorSnack(context, '$e');
                                }
                              }
                            }),
                        if (widget.backend.syncAccount != null)
                          OutlinedButton(
                              onPressed: () async {
                                try {
                                  await widget.backend.syncAccount!();
                                  await _loadData();
                                } catch (e) {
                                  if (context.mounted) {
                                    showErrorSnack(context, '$e');
                                  }
                                }
                              },
                              child: const Text('Sync now')),
                        if (widget.backend.useLocalProjects != null)
                          TextButton(
                              onPressed: () async {
                                try {
                                  await widget.backend.useLocalProjects!();
                                  await _loadData();
                                } catch (e) {
                                  if (context.mounted) {
                                    showErrorSnack(context, '$e');
                                  }
                                }
                              },
                              child: const Text('Local projects')),
                      ]),
                      const Divider(height: 32),
                    ],
                    _buildThisDeviceCard(theme),

                    const SizedBox(height: 16),

                    // ── Devices (servers + paired devices, incl. QR pairing) ──
                    ServerSettingsSection(
                        backend: widget.backend, onServerChanged: _loadData),

                    const Divider(height: 32),

                    // ── Identity ──
                    _buildIdentitySection(theme),

                    const Divider(height: 32),

                    // ── Drives ──
                    _buildDrivesSection(theme),
                  ],
                ),
              ),
            ),
      actions: [
        if (widget.backend.signOut != null)
          TextButton(
            onPressed: _signOut,
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('Sign out'),
          ),
        TextButton(
          onPressed: () => Navigator.pop(context, false),
          child: const Text('Done'),
        ),
      ],
    );
  }

  // ── Sync Section ──────────────────────────────────────────────────────

  /// This device, always shown first — the browser Sync page leads with the
  /// same card. It is the one device you are looking *from*.
  Widget _buildThisDeviceCard(ThemeData theme) {
    final isOnline = _peerId != null;

    return _deviceCard(
      theme,
      icon: Icons.phone_android,
      title: _deviceName.isNotEmpty ? _deviceName : 'This device',
      onTitleTap: () async {
        final controller = TextEditingController(text: _deviceName);
        final newName = await showDialog<String>(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Text('Device name'),
            content: TextField(
              controller: controller,
              autofocus: true,
              decoration: const InputDecoration(
                hintText: 'Enter device name',
                border: OutlineInputBorder(),
              ),
              onSubmitted: (v) => Navigator.pop(ctx, v.trim()),
            ),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: const Text('Cancel')),
              TextButton(
                onPressed: () => Navigator.pop(ctx, controller.text.trim()),
                child: const Text('Save'),
              ),
            ],
          ),
        );
        if (newName != null && newName.isNotEmpty) {
          try {
            await widget.backend.setDeviceName(newName);
            if (mounted) setState(() => _deviceName = newName);
          } catch (e) {
            if (mounted) showErrorSnack(context, 'Could not rename device: $e');
          }
        }
      },
      status: isOnline ? 'Online' : (_peerStarting ? 'Starting...' : 'Offline'),
      statusColor: isOnline ? Colors.green : theme.colorScheme.onSurfaceVariant,
      details: [
        if (_peerId != null)
          _miniDetail('Device ID', _shortId(_peerId!, 16),
              onCopy: () => _copyToClipboard(_peerId!, 'Device ID')),
        if (_activeDrive != null)
          _miniDetail(
              'Drive',
              _driveNames[_activeDrive]?.isNotEmpty == true
                  ? _driveNames[_activeDrive]!
                  : _shortId(_activeDrive!, 16)),
      ],
    );
  }

  Widget _deviceCard(
    ThemeData theme, {
    required IconData icon,
    required String title,
    required String status,
    required Color statusColor,
    List<Widget> details = const [],
    VoidCallback? onTitleTap,
  }) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
            color: theme.colorScheme.outlineVariant.withValues(alpha: 0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 20, color: theme.colorScheme.onSurface),
              const SizedBox(width: 8),
              Expanded(
                  child: GestureDetector(
                onTap: onTitleTap,
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Flexible(
                        child: Text(title,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                                fontSize: 13, fontWeight: FontWeight.w600))),
                    if (onTitleTap != null) ...[
                      const SizedBox(width: 4),
                      Icon(Icons.edit,
                          size: 12, color: theme.colorScheme.onSurfaceVariant),
                    ],
                  ],
                ),
              )),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: statusColor.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(status,
                    style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w600,
                        color: statusColor)),
              ),
            ],
          ),
          if (details.isNotEmpty) ...[
            const SizedBox(height: 8),
            ...details,
          ],
        ],
      ),
    );
  }

  Widget _miniDetail(String label, String value, {VoidCallback? onCopy}) {
    return Padding(
      padding: const EdgeInsets.only(top: 2),
      child: Row(
        children: [
          SizedBox(
            width: 65,
            child: Text(label,
                style: TextStyle(
                    fontSize: 11,
                    color: Theme.of(context).colorScheme.onSurfaceVariant)),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(fontSize: 11),
                overflow: TextOverflow.ellipsis),
          ),
          if (onCopy != null)
            GestureDetector(
              onTap: onCopy,
              child: Text('Copy',
                  style: TextStyle(
                      fontSize: 10,
                      color: Theme.of(context).colorScheme.primary)),
            ),
        ],
      ),
    );
  }

  // ── Identity Section ─────────────────────────────────────────────────

  Widget _buildIdentitySection(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _sectionTitle('Identity'),
        if (_agent != null) ...[
          _miniDetail('Name', _agent!.name ?? 'Anonymous'),
          _miniDetail('DID', _shortId(_agent!.subject, 24),
              onCopy: () => _copyToClipboard(_agent!.subject, 'DID')),
          const SizedBox(height: 4),
          OutlinedButton.icon(
            icon: const Icon(Icons.key, size: 14),
            label: const Text('Copy Secret', style: TextStyle(fontSize: 12)),
            onPressed: () async {
              try {
                final secret = await widget.backend.exportSecret();
                if (mounted) _copyToClipboard(secret, 'Secret');
              } catch (e) {
                if (mounted) {
                  showErrorSnack(context, 'Could not copy secret: $e');
                }
              }
            },
          ),
        ] else
          Text('No agent',
              style: TextStyle(
                  fontSize: 13,
                  color: Theme.of(context).colorScheme.onSurfaceVariant)),
        if (widget.backend.signIn != null)
          TextButton.icon(
              icon: const Icon(Icons.login, size: 14),
              label: const Text('Sign in with a secret'),
              onPressed: () async {
                try {
                  await widget.backend.signIn!(context);
                  if (mounted) await _loadData();
                } catch (e) {
                  if (mounted) showErrorSnack(context, 'Could not sign in: $e');
                }
              }),
      ],
    );
  }

  // ── Drives Section ───────────────────────────────────────────────────

  Widget _buildDrivesSection(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _sectionTitle('Drives'),
        if (_drives.isEmpty)
          Text('No drives',
              style: TextStyle(
                  fontSize: 13,
                  color: Theme.of(context).colorScheme.onSurfaceVariant))
        else
          ..._drives.map((d) => _driveTile(d)),
        if (_showNewDrive) ...[
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _newDriveController,
                  autofocus: true,
                  decoration: const InputDecoration(
                    hintText: 'Drive name',
                    border: OutlineInputBorder(),
                    isDense: true,
                    contentPadding:
                        EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                  onSubmitted: (_) => _createDrive(),
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                icon: _creatingDrive
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.check, size: 20),
                onPressed: _creatingDrive ? null : _createDrive,
              ),
              IconButton(
                icon: const Icon(Icons.close, size: 20),
                onPressed: () => setState(() => _showNewDrive = false),
              ),
            ],
          ),
        ] else
          TextButton.icon(
            icon: const Icon(Icons.add, size: 14),
            label: const Text('New drive', style: TextStyle(fontSize: 12)),
            style: TextButton.styleFrom(
              foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
              padding: const EdgeInsets.symmetric(horizontal: 4),
            ),
            onPressed: () => setState(() => _showNewDrive = true),
          ),
      ],
    );
  }

  String _shortId(String id, int length) =>
      id.length <= length ? id : '${id.substring(0, length)}...';

  // ── Helpers ──────────────────────────────────────────────────────────

  Widget _driveTile(String drive) {
    final isActive = drive == _activeDrive;
    final name = _driveNames[drive];
    final label = (name != null && name.isNotEmpty)
        ? name
        : (drive.length > 30
            ? '${drive.substring(0, 12)}...${drive.substring(drive.length - 8)}'
            : drive);
    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      leading: Icon(
        isActive ? Icons.check_circle : Icons.circle_outlined,
        color: isActive ? Theme.of(context).colorScheme.primary : Colors.grey,
        size: 20,
      ),
      title: Text(label, style: const TextStyle(fontSize: 13)),
      onTap: () => _switchDrive(drive),
    );
  }

  Widget _sectionTitle(String title) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Text(
        title,
        style: TextStyle(
          fontSize: 13,
          fontWeight: FontWeight.w600,
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
}
