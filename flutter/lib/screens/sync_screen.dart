import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:webview_flutter/webview_flutter.dart' show WebViewCookie;

import 'package:atomic_chat/atomic_chat.dart'
    show AppTopBar, ResourceWebView, openResourceView, timeAgo;

import '../assistant/atomic_assistant_api.dart';
import '../atomic/account_store.dart';
import '../atomic/atomic_client.dart';
import '../atomic/settings_backend.dart';
import '../theme.dart';
import 'account_link_dialog.dart';
import 'edit_profile_screen.dart';

/// The person's picture in a circle when they have one, else their emoji icon,
/// else their initial: the way into the agent and sync screen.
class AgentAvatar extends StatelessWidget {
  final String? name;
  final double radius;

  /// The agent's picture (its `icon` File's download URL).
  final String? imageUrl;

  /// The agent's emoji icon.
  final String? emoji;

  const AgentAvatar(
      {super.key, this.name, this.radius = 16, this.imageUrl, this.emoji});

  /// The same circle for an identity.
  factory AgentAvatar.of(shared.AtomicIdentity? agent, {double radius = 16}) =>
      AgentAvatar(
          name: agent?.name,
          imageUrl: agent?.imageUrl,
          emoji: agent?.emoji,
          radius: radius);

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final trimmed = name?.trim() ?? '';
    final icon = emoji?.trim() ?? '';
    final Widget fallback = icon.isNotEmpty
        ? Text(icon, style: TextStyle(fontSize: radius))
        : trimmed.isEmpty
            ? Icon(Icons.person, size: radius * 1.1, color: c.mainSelectedFg)
            : Text(trimmed.characters.first.toUpperCase(),
                style: TextStyle(
                    color: c.mainSelectedFg,
                    fontWeight: FontWeight.w600,
                    fontSize: radius * 0.9));
    final url = imageUrl?.trim() ?? '';
    return CircleAvatar(
      radius: radius,
      backgroundColor: c.mainSelectedBg,
      child: url.isEmpty
          ? fallback
          : ClipOval(
              child: Image.network(
                url,
                width: radius * 2,
                height: radius * 2,
                fit: BoxFit.cover,
                // Offline, or a picture this device may not read: the
                // initial instead.
                errorBuilder: (_, __, ___) => Center(child: fallback),
              ),
            ),
    );
  }
}

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

  void _fail(String what, Object e) => ScaffoldMessenger.of(context)
      .showSnackBar(SnackBar(content: Text('$what: $e')));

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
        builder: (_) => EditProfileScreen(agent: agent, save: save),
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
              className: 'agent',
            ),
      ));
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
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: const AppTopBar(title: 'Sync'),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 32),
              children: [
                if (_error != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: Text(_error!, style: TextStyle(color: c.alert)),
                  ),
                _identity(c),
                _workspaceSwitcher(c),
                if (_account != null || _accountError != null) _account_(c),
                if (_account == null && _portal != null) _linkRow(c, _portal!),
                _group(c, 'This device', [_thisDevice(c)]),
                // Servers, paired devices and the pairing code: the browser's
                // Devices list.
                Padding(
                  padding: const EdgeInsets.only(top: 20),
                  child: shared.ServerSettingsSection(
                    backend: _backend,
                    onServerChanged: _load,
                  ),
                ),
              ],
            ),
    );
  }

  /// One row: the current workspace. It opens a sheet to switch, so the page
  /// is not a list of every workspace.
  Widget _workspaceSwitcher(AppColors c) {
    final active = _activeDrive;
    return Padding(
      padding: const EdgeInsets.only(top: 16),
      child: Material(
        color: c.bgBody,
        shape: RoundedRectangleBorder(
          side: BorderSide(color: c.textSecondary.withValues(alpha: 0.3)),
          borderRadius: BorderRadius.circular(12),
        ),
        child: ListTile(
          dense: true,
          leading: Icon(Icons.folder_outlined, color: c.main),
          title: Text(active == null ? 'No workspace' : _driveLabel(active)),
          subtitle: const Text('Workspace'),
          trailing: Icon(Icons.expand_more, color: c.textSecondary),
          onTap: _pickWorkspace,
        ),
      ),
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
    final c = context.appColors;
    final picked = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      backgroundColor: c.bgBody,
      builder: (ctx) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            for (final d in shown)
              ListTile(
                leading: Icon(
                    d == _activeDrive
                        ? Icons.radio_button_checked
                        : Icons.radio_button_off,
                    color: c.main),
                title: Text(_driveLabel(d)),
                onTap: () => Navigator.pop(ctx, d),
              ),
            if (elsewhere > 0)
              ListTile(
                leading:
                    Icon(Icons.cloud_download_outlined, color: c.textSecondary),
                title: Text(
                    '$elsewhere more workspace${elsewhere == 1 ? '' : 's'} not on this device yet'),
              ),
            ListTile(
              leading: Icon(Icons.add, color: c.main),
              title: const Text('New workspace'),
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

  Widget _group(AppColors c, String title, List<Widget> children) => Padding(
        padding: const EdgeInsets.only(top: 20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Text(title,
                  style: TextStyle(
                      color: c.textSecondary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600)),
            ),
            Material(
              color: c.bg1,
              borderRadius: BorderRadius.circular(12),
              clipBehavior: Clip.antiAlias,
              child: Column(children: children),
            ),
          ],
        ),
      );

  Widget _identity(AppColors c) {
    final agent = _agent;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        InkWell(
          onTap: agent == null ? null : _openProfile,
          borderRadius: BorderRadius.circular(12),
          child: Row(children: [
            AgentAvatar.of(agent, radius: 28),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    (agent?.name?.isNotEmpty ?? false) ? agent!.name! : 'You',
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                  if (agent != null)
                    GestureDetector(
                      onTap: () => _copy(agent.subject, 'Agent ID'),
                      child: Text(_short(agent.subject),
                          style:
                              TextStyle(color: c.textSecondary, fontSize: 12)),
                    ),
                ],
              ),
            ),
            if (agent != null)
              Icon(Icons.chevron_right, color: c.textSecondary),
          ]),
        ),
        const SizedBox(height: 12),
        Wrap(spacing: 8, children: [
          OutlinedButton.icon(
            icon: const Icon(Icons.key, size: 16),
            label: const Text('Copy secret key'),
            onPressed: _copySecret,
          ),
          if (_backend.signOut != null)
            OutlinedButton.icon(
              icon: const Icon(Icons.logout, size: 16),
              label: const Text('Sign out'),
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
      return _group(c, 'Account', [
        ListTile(
          leading: Icon(Icons.error_outline, color: c.alert),
          title: const Text('Could not read your account'),
          subtitle: Text(_accountError ?? ''),
          trailing:
              TextButton(onPressed: _loadAccount, child: const Text('Retry')),
        ),
      ]);
    }
    final vault = account.vault;
    final server = account.server;
    return _group(c, 'Account', [
      ListTile(
        leading: Icon(Icons.alternate_email, color: c.main),
        title: Text(account.address),
        subtitle: Text(account.portal.host),
      ),
      ListTile(
        leading: Icon(Icons.shield_outlined, color: c.main),
        title: const Text('Cloud Vault'),
        subtitle: Text(vault == null
            ? 'Off for ${_driveLabel(_activeDrive ?? '')}'
            : _vaultLine(vault)),
      ),
      ListTile(
        leading: Icon(Icons.cloud_outlined, color: c.main),
        title: const Text('Cloud Server'),
        subtitle: Text(server == null
            ? 'Off for ${_driveLabel(_activeDrive ?? '')}'
            : _serverLine(server)),
      ),
      ListTile(
        leading: Icon(Icons.auto_awesome_outlined, color: c.main),
        title: const Text('AI credits'),
        subtitle: Text(_creditsLine()),
        trailing: _creditsLoading
            ? const SizedBox.square(
                dimension: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : IconButton(
                tooltip: 'Refresh AI credits',
                icon: const Icon(Icons.refresh),
                onPressed: _loadCredits),
      ),
      if (_credits?.purchasesEnabled == true)
        ListTile(
          leading: Icon(Icons.add_card_outlined, color: c.main),
          title: const Text('Get more credits'),
          onTap: () => _openInBrowser(account.portal
              .replace(path: '/dashboard', query: null, fragment: null)),
        ),
      ListTile(
        leading: Icon(Icons.open_in_new, color: c.main),
        title: const Text('Manage in the portal'),
        trailing: _openingPortal
            ? const SizedBox.square(
                dimension: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : null,
        onTap: () => _openPortal(account.portal),
      ),
      ListTile(
        leading: Icon(Icons.link_off, color: c.textSecondary),
        title: const Text('Unlink this device'),
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

  Widget _linkRow(AppColors c, String portal) => _group(c, 'Account', [
        ListTile(
          leading: Icon(Icons.link, color: c.main),
          title: const Text('Link your account'),
          subtitle: Text(
              'Show Cloud Vault and Cloud Server from ${Uri.tryParse(portal)?.host ?? portal}'),
          onTap: () => _link(portal),
        ),
      ]);

  Widget _thisDevice(AppColors c) {
    final online = _peerId != null;
    return ListTile(
      leading: Icon(Icons.phone_android, color: c.main),
      title: Text(_deviceName.isEmpty ? 'This device' : _deviceName),
      subtitle: Text([
        online ? 'Online' : 'Offline',
        if (_peerId != null) _short(_peerId!),
      ].join(' · ')),
      trailing: const Icon(Icons.edit_outlined, size: 18),
      onTap: _rename,
      onLongPress: _peerId == null ? null : () => _copy(_peerId!, 'Device ID'),
    );
  }

  static String _short(String id) => id.length <= 22
      ? id
      : '${id.substring(0, 12)}…${id.substring(id.length - 6)}';
}
