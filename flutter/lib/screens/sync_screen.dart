import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:webview_flutter/webview_flutter.dart' show WebViewCookie;

import 'package:atomic_chat/atomic_chat.dart'
    show
        AppTopBar,
        ProfileAvatar,
        readableHorizontalPadding,
        openFromList,
        ResourceView,
        ResourceWebView,
        openResourceView,
        timeAgo;

import '../assistant/atomic_assistant_api.dart';
import '../atomic/account_store.dart';
import '../atomic/atomic_client.dart';
import '../atomic/settings_backend.dart';
import '../theme.dart';
import 'account_link_dialog.dart';
import 'edit_profile_screen.dart';
import 'this_device_card.dart';

/// The circle for an identity: its picture, else emoji, else initial.
Widget agentAvatar(shared.AtomicIdentity? agent, {double radius = 16}) =>
    ProfileAvatar(
        name: agent?.name,
        imageUrl: agent?.imageUrl,
        imageBytes: agent?.imageBytes,
        emoji: agent?.emoji,
        radius: radius);

/// Hides the portal's own top bar: the app already has its own.
const portalChromeCss = 'nav.topbar{display:none!important}';

/// Your agent and everything that syncs, after the web app's Sync page:
/// who you are, the account that hosts your data (only when one is linked),
/// this device and the devices it syncs with, and the workspaces. Sync is set
/// per workspace; the account section speaks about the active one.
///
/// Pops with true when the person signed out.
class SyncScreen extends StatefulWidget {
  final shared.AtomicSettingsBackend? backend;
  final Future<AccountSummary?> Function(String? drive)? loadAccount;
  final Future<void> Function(BuildContext context, String portal)? linkAccount;

  /// The account's AI credits; [AccountStore.aiCredits] by default.
  final Future<shared.AtomicAiCredits?> Function()? loadCredits;

  /// The portal sign-in cookie for the web view; [AccountStore.portalCookie]
  /// by default.
  final Future<String?> Function(Uri portal)? portalCookie;

  /// Test seam for the page the agent profile opens in.
  @visibleForTesting
  final Widget Function(String subject)? profilePage;

  /// Test seam for the page a drive's storage opens in: the drive subject and
  /// the page title.
  @visibleForTesting
  final Widget Function(String drive, String title)? storagePage;

  /// Test seam for the page the portal opens in.
  @visibleForTesting
  final Widget Function(ResourceWebView page)? portalPage;

  const SyncScreen({
    super.key,
    this.backend,
    this.loadAccount,
    this.linkAccount,
    this.loadCredits,
    this.portalCookie,
    this.portalPage,
    this.profilePage,
    this.storagePage,
  });

  @override
  State<SyncScreen> createState() => _SyncScreenState();
}

class _SyncScreenState extends State<SyncScreen> {
  late final shared.AtomicSettingsBackend _backend =
      widget.backend ?? AppSettingsBackend();

  bool _loading = true;
  String? _error;
  shared.AtomicIdentity? _agent;
  String _deviceName = '';
  String? _peerId;
  String? _activeDrive;
  Map<String, String> _drives = {};
  AccountSummary? _account;
  String? _accountError;

  /// Last known AI credits, kept when a refresh fails (offline).
  shared.AtomicAiCredits? _credits;
  bool _creditsLoading = false;
  bool _creditsFailed = false;

  /// Where the active server is administered, when it is a managed one: the
  /// only place an account can be linked from.
  String? _portal;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    List<String> drives = const [];
    try {
      final agent = await _backend.getActiveAgent();
      final deviceName = await _backend.getDeviceName();
      final peerId = await _backend.getPeerId();
      if (!mounted) return;
      // Show the screen now; a person with many drives must not wait for
      // every drive's name before seeing their own devices.
      setState(() {
        _agent = agent;
        _deviceName = deviceName;
        _peerId = peerId;
        _activeDrive = _backend.getActiveDrive();
        _error = null;
        _loading = false;
      });
      // Listing the drives reads each one, which is slow with many: after the
      // screen is up.
      drives = await _backend.listDrives();
      if (!mounted) return;
      setState(() => _drives = {for (final d in drives) d: _drives[d] ?? ''});
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
          _loading = false;
        });
      }
    }
    unawaited(_loadAccount());
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

  /// Where an account can be linked: the portal a known server reports for
  /// itself (the active one first). A self-hosted server names none, so a
  /// person who never used a hosted account is never offered one.
  Future<String?> _findPortal() async {
    final servers = _backend.servers;
    if (servers == null) return null;
    try {
      final active = await servers.activeServer();
      final known = await servers.knownServers();
      final order = [
        if (active != null) active,
        ...known.where((k) => k != active),
      ];
      final infos = await Future.wait([
        for (final url in order)
          servers
              .serverInfo(url)
              .timeout(const Duration(seconds: 6))
              .then<String?>((i) => i.managed ? i.portalUrl : null)
              .catchError((Object _) => null),
      ]);
      return infos.whereType<String>().firstOrNull;
    } catch (_) {
      return null;
    }
  }

  Future<void> _loadAccount() async {
    AccountSummary? account;
    String? accountError;
    String? portal;
    try {
      account =
          await (widget.loadAccount ?? AccountStore.summary)(_activeDrive);
    } catch (e) {
      accountError = '$e';
    }
    if (account == null) portal = await _findPortal();
    if (!mounted) return;
    setState(() {
      _account = account;
      _accountError = accountError;
      _portal = portal;
    });
    if (account != null) unawaited(_loadCredits());
  }

  Future<void> _loadCredits() async {
    if (_creditsLoading) return;
    setState(() => _creditsLoading = true);
    var failed = false;
    shared.AtomicAiCredits? credits = _credits;
    try {
      credits = await (widget.loadCredits ?? AccountStore.aiCredits)();
    } catch (_) {
      failed = true;
    }
    if (!mounted) return;
    setState(() {
      _credits = credits;
      _creditsLoading = false;
      _creditsFailed = failed;
    });
  }

  String _creditsLine() {
    final credits = _credits;
    if (credits == null) return _creditsFailed ? 'Could not load' : '—';
    return [
      if (credits.allowance > 0)
        '${credits.remaining} of ${credits.allowance} this month'
      else
        '${credits.remaining} left',
      if (credits.purchased > 0) '${credits.purchased} purchased',
      if (_creditsFailed) 'offline, last known',
    ].join(' · ');
  }

  void _copy(String text, String what) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('$what copied')));
  }

  void _fail(String what, Object e) =>
      shared.showErrorSnack(context, '$what: $e');

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
        await _ask('Device name', 'Name this device', initial: _deviceName);
    if (name == null || name.isEmpty) return;
    try {
      await _backend.setDeviceName(name);
      if (mounted) setState(() => _deviceName = name);
    } catch (e) {
      if (mounted) _fail('Could not rename the device', e);
    }
  }

  /// The agent's profile: the native editor when the backend can save it,
  /// else the agent's own page in the embedded web renderer.
  Future<void> _openProfile() async {
    final agent = _agent;
    final drive = _activeDrive;
    if (agent == null) return;
    final save = _backend.saveProfile;
    if (save != null && widget.profilePage == null) {
      await Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) => EditProfileScreen(
            agent: agent, save: save, pickPicture: _backend.pickProfilePicture),
      ));
    } else {
      if (drive == null) return;
      await Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) =>
            widget.profilePage?.call(agent.subject) ??
            openResourceView(
              api: const AtomicAssistantApi(),
              drive: drive,
              subject: agent.subject,
              title: (agent.name?.isNotEmpty ?? false) ? agent.name! : 'You',
            ),
      ));
    }
    if (mounted) await _load();
  }

  /// The web app's settings page, like the storage page: in the detail pane
  /// next to the list, else pushed.
  void _openSettings() {
    final drive = _activeDrive ?? '';
    Widget build(BuildContext _) => ResourceView(
        api: const AtomicAssistantApi(),
        drive: drive,
        title: 'Settings',
        path: '/app/settings');
    openFromList<void>(context, build, subject: '$drive#settings');
  }

  /// The web app's storage page for [drive], in the shell's detail pane next
  /// to the list, else pushed with the native app bar.
  void _openStorage(String drive, String name) {
    final title = 'Storage · $name';
    Widget build(BuildContext _) =>
        widget.storagePage?.call(drive, title) ??
        ResourceView(
            api: const AtomicAssistantApi(),
            drive: drive,
            title: title,
            path: '/app/storage');
    openFromList<void>(context, build, subject: '$drive#storage');
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

  Future<void> _signOut() async {
    final navigator = Navigator.of(context);
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
      await AccountStore.clear();
      await _backend.signOut!();
      if (navigator.mounted) navigator.pop(true);
    } catch (e) {
      if (mounted) _fail('Could not sign out', e);
    }
  }

  bool _openingPortal = false;

  /// Opens the portal already signed in as the agent, so the person does not
  /// meet a second login; without a cookie it opens as it always did.
  Future<void> _openPortal(Uri portal) async {
    final url = shared.AtomicAccountClient.portalDrivesUrl(portal);
    if (_openingPortal) return;
    setState(() => _openingPortal = true);
    String? cookie;
    try {
      cookie = await (widget.portalCookie ?? AccountStore.portalCookie)(url);
    } catch (_) {
      cookie = null;
    }
    if (!mounted) return;
    setState(() => _openingPortal = false);
    final page = ResourceWebView(
      api: const AtomicAssistantApi(),
      subject: url.toString(),
      url: url.toString(),
      title: url.host,
      keepOnHost: true,
      injectCss: portalChromeCss,
      cookies: [
        if (cookie != null && cookie.isNotEmpty)
          WebViewCookie(name: 'session_token', value: cookie, domain: url.host),
      ],
    );
    await Navigator.of(context).push(MaterialPageRoute<void>(
      builder: (_) => widget.portalPage?.call(page) ?? page,
    ));
    // Credits may have been bought or used while away.
    if (mounted) unawaited(_loadCredits());
  }

  /// In the system browser: it is where the emailed sign-in link will open,
  /// and where a passkey lives.
  Future<void> _openInBrowser(Uri url) async {
    final opened = await launchUrl(url, mode: LaunchMode.externalApplication);
    if (!opened && mounted) _fail('Could not open the browser', url.host);
  }

  Future<void> _link(String portal) async {
    try {
      if (widget.linkAccount != null) {
        await widget.linkAccount!(context, portal);
      } else {
        await showDialog<bool>(
          context: context,
          barrierDismissible: false,
          builder: (_) => AccountLinkDialog(
            client: shared.AtomicAccountClient(portal),
            deviceName: _deviceName.isEmpty ? 'atomic.place' : _deviceName,
            save: AccountStore.save,
            openInBrowser: _openInBrowser,
          ),
        );
      }
      await _loadAccount();
    } catch (e) {
      if (mounted) _fail('Could not link the account', e);
    }
  }

  Future<void> _unlink() async {
    await AccountStore.clear();
    await _loadAccount();
  }

  String _driveLabel(String drive) =>
      (_drives[drive]?.isNotEmpty ?? false) ? _drives[drive]! : 'Workspace';

  @override
  Widget build(BuildContext context) {
    final c = shared.syncColors(context);
    return Scaffold(
      backgroundColor: c.bgBody,
      // The user panel: the page is about you and your devices; the web
      // app's settings are one tap away (and nowhere else in the app).
      appBar: AppTopBar(
        title: 'User',
        actions: [
          TextButton.icon(
            key: const ValueKey('sync-open-settings'),
            onPressed: _openSettings,
            icon: const Icon(Icons.settings_outlined, size: 20),
            label: const Text('Settings'),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          // A tablet's detail pane: a readable column, centred.
          : LayoutBuilder(
              builder: (context, box) => ListView(
                    padding: readableHorizontalPadding(box.maxWidth,
                            gutter: shared.SyncGap.l)
                        .copyWith(top: shared.SyncGap.xs, bottom: 32),
                    children: [
                      if (_error != null)
                        Padding(
                          padding:
                              const EdgeInsets.only(bottom: shared.SyncGap.m),
                          child: shared.SyncNote(_error!,
                              tone: shared.SyncTone.error,
                              icon: Icons.error_outline),
                        ),
                      _identity(c),
                      _workspaceSwitcher(c),
                      if (_account != null || _accountError != null)
                        _account_(c),
                      if (_account == null && _portal != null)
                        _linkRow(c, _portal!),
                      ThisDeviceCard(
                        backend: _backend,
                        deviceName: _deviceName,
                        peerId: _peerId,
                        identity: _agent?.subject,
                        driveNames: _drives,
                        onRename: _rename,
                        onOpenStorage: _openStorage,
                      ),
                      // Servers, paired devices and the pairing code: the browser's
                      // Devices list.
                      shared.ServerSettingsSection(
                        backend: _backend,
                        onServerChanged: _load,
                      ),
                    ],
                  )),
    );
  }

  /// One row: the current workspace. It opens a sheet to switch, so the page
  /// is not a list of every workspace.
  Widget _workspaceSwitcher(AppColors c) {
    final active = _activeDrive;
    return Padding(
      padding: const EdgeInsets.only(top: shared.SyncGap.l),
      child: shared.SyncCard(children: [
        shared.SyncRow(
          icon: Icons.folder_outlined,
          title: active == null ? 'No workspace' : _driveLabel(active),
          subtitle: 'Workspace',
          trailing: Icon(Icons.expand_more, size: 24, color: c.textSecondary),
          onTap: _pickWorkspace,
        ),
      ]),
    );
  }

  /// The workspaces that are on this device, each once. Listed drives that
  /// have not been received (no name yet) are one line, not forty.
  Future<void> _pickWorkspace() async {
    final seen = <String>{};
    final shown = <String>[];
    var elsewhere = 0;
    for (final d in _drives.keys) {
      if (!seen.add(AtomicClient.driveKey(d))) continue;
      final named = (_drives[d] ?? '').isNotEmpty;
      if (named || d == _activeDrive) {
        shown.add(d);
      } else {
        elsewhere++;
      }
    }
    final c = shared.syncColors(context);
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
              shared.SyncRow(
                icon: d == _activeDrive
                    ? Icons.radio_button_checked
                    : Icons.radio_button_off,
                title: _driveLabel(d),
                onTap: () => Navigator.pop(ctx, d),
              ),
            if (elsewhere > 0)
              shared.SyncRow(
                icon: Icons.cloud_download_outlined,
                iconColor: c.textSecondary,
                title:
                    '$elsewhere more workspace${elsewhere == 1 ? '' : 's'} not on this device yet',
              ),
            shared.SyncRow(
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

  Widget _identity(AppColors c) {
    final agent = _agent;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        InkWell(
          mouseCursor: WidgetStateMouseCursor.clickable,
          onTap: agent == null ? null : _openProfile,
          borderRadius: BorderRadius.circular(12),
          child: Row(children: [
            agentAvatar(agent, radius: 28),
            const SizedBox(width: shared.SyncGap.l),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    (agent?.name?.isNotEmpty ?? false) ? agent!.name! : 'You',
                    style: shared.SyncText.title(c),
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
                          padding: const EdgeInsets.symmetric(
                              vertical: shared.SyncGap.s),
                          child: Row(mainAxisSize: MainAxisSize.min, children: [
                            Flexible(
                              child: Text(shared.shortId(agent.subject),
                                  overflow: TextOverflow.ellipsis,
                                  style: shared.SyncText.caption(c)),
                            ),
                            const SizedBox(width: shared.SyncGap.s),
                            Icon(Icons.copy, size: 20, color: c.textSecondary),
                          ]),
                        ),
                      ),
                    ),
                ],
              ),
            ),
            if (agent != null)
              Icon(Icons.chevron_right, size: 24, color: c.textSecondary),
          ]),
        ),
        const SizedBox(height: shared.SyncGap.m),
        Wrap(
            spacing: shared.SyncGap.s,
            runSpacing: shared.SyncGap.s,
            children: [
              if (agent != null)
                shared.SyncActionButton(
                  icon: Icons.edit_outlined,
                  label: 'Edit profile',
                  onPressed: _openProfile,
                ),
              shared.SyncActionButton(
                icon: Icons.key,
                label: 'Copy secret key',
                onPressed: _copySecret,
              ),
              if (_backend.signOut != null)
                shared.SyncActionButton(
                  icon: Icons.logout,
                  label: 'Sign out',
                  onPressed: _signOut,
                ),
            ]),
      ],
    );
  }

  /// Only for a linked account: address, Cloud Vault and Cloud Server for the
  /// active workspace, and the way to the portal.
  Widget _account_(AppColors c) {
    final account = _account;
    if (account == null) {
      return shared.SyncSection(title: 'Account', children: [
        shared.SyncRow(
          icon: Icons.error_outline,
          iconColor: c.alert,
          title: 'Could not read your account',
          subtitle: '',
          trailing:
              shared.SyncTextAction(label: 'Retry', onPressed: _loadAccount),
        ),
        if (_accountError != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(
                shared.SyncGap.l, 0, shared.SyncGap.l, shared.SyncGap.m),
            child: shared.ErrorText(_accountError!, color: c.alert),
          ),
      ]);
    }
    final vault = account.vault;
    final server = account.server;
    return shared.SyncSection(title: 'Account', children: [
      shared.SyncRow(
        icon: Icons.alternate_email,
        title: account.address,
        subtitle: account.portal.host,
      ),
      shared.SyncRow(
        icon: Icons.shield_outlined,
        title: 'Cloud Vault',
        subtitle: vault == null
            ? 'Off for ${_driveLabel(_activeDrive ?? '')}'
            : _vaultLine(vault),
      ),
      shared.SyncRow(
        icon: Icons.cloud_outlined,
        title: 'Cloud Server',
        subtitle: server == null
            ? 'Off for ${_driveLabel(_activeDrive ?? '')}'
            : _serverLine(server),
      ),
      shared.SyncRow(
        icon: Icons.auto_awesome_outlined,
        title: 'AI credits',
        subtitle: _creditsLine(),
        trailing: _creditsLoading
            ? const shared.SyncSpinner()
            : IconButton(
                tooltip: 'Refresh AI credits',
                icon: const Icon(Icons.refresh, size: 24),
                constraints: const BoxConstraints(minWidth: 48, minHeight: 48),
                onPressed: _loadCredits),
      ),
      if (_credits?.purchasesEnabled == true)
        shared.SyncRow(
          icon: Icons.add_card_outlined,
          title: 'Get more credits',
          onTap: () => _openInBrowser(account.portal
              .replace(path: '/dashboard', query: null, fragment: null)),
        ),
      shared.SyncRow(
        icon: Icons.open_in_new,
        title: 'Manage in the portal',
        trailing: _openingPortal ? const shared.SyncSpinner() : null,
        onTap: () => _openPortal(account.portal),
      ),
      shared.SyncRow(
        icon: Icons.link_off,
        iconColor: c.textSecondary,
        title: 'Unlink this device',
        onTap: _unlink,
      ),
    ]);
  }

  String _vaultLine(Map<String, dynamic> vault) {
    final last = vault['last_backup_at'];
    final used = vault['used_bytes'];
    return [
      'On',
      if (last is num && last > 0)
        'last backup ${timeAgo(last.toInt() > 100000000000 ? last.toInt() : last.toInt() * 1000)}',
      if (used is num) shared.formatBytes(used.toInt()),
    ].join(' · ');
  }

  String _serverLine(Map<String, dynamic> server) {
    final origin = server['http_origin'];
    final count = server['resource_count'];
    final bytes = ((server['blob_bytes'] as num?) ?? 0) +
        ((server['loro_bytes'] as num?) ?? 0);
    return [
      'On',
      if (origin is String && origin.isNotEmpty) Uri.parse(origin).host,
      if (count is num) '${count.toInt()} resources',
      if (bytes > 0) shared.formatBytes(bytes.toInt()),
    ].join(' · ');
  }

  Widget _linkRow(AppColors c, String portal) =>
      shared.SyncSection(title: 'Account', children: [
        shared.SyncRow(
          icon: Icons.link,
          title: 'Link your account',
          subtitle:
              'Show Cloud Vault and Cloud Server from ${Uri.tryParse(portal)?.host ?? portal}',
          onTap: () => _link(portal),
        ),
      ]);
}
