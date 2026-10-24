import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
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
        BackgroundActivity,
        BackgroundState,
        timeAgo,
        ToastScope;

import '../assistant/atomic_assistant_api.dart';
import '../atomic/account_store.dart';
import '../atomic/settings_backend.dart';
import 'account_link_dialog.dart';
import 'edit_profile_screen.dart';
import 'login_screen.dart';

/// Where the Storage row's expanded state is kept.
const _storageExpandedKey = 'sync_storage_expanded';

/// What the app does in the background; counts only while it is shown.
class _BackgroundActivityRow extends StatefulWidget {
  const _BackgroundActivityRow();

  @override
  State<_BackgroundActivityRow> createState() => _BackgroundActivityRowState();
}

class _BackgroundActivityRowState extends State<_BackgroundActivityRow> {
  @override
  void initState() {
    super.initState();
    BackgroundActivity.instance.start();
  }

  @override
  void dispose() {
    BackgroundActivity.instance.stop();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => ValueListenableBuilder<BackgroundState>(
        valueListenable: BackgroundActivity.instance,
        builder: (context, activity, _) => shared.KeyValueRow(
          key: const Key('background-activity-row'),
          label: 'Background activity',
          value: activity.summary,
          // A failure's text is copied with a tap.
          copy: activity.problem ? activity.lastError : null,
          copyLabel: 'Error',
          icon: activity.busy
              ? Icons.sync
              : activity.problem
                  ? Icons.sync_problem
                  : Icons.check_circle_outline,
        ),
      );
}

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

/// The app's User page: the shared [shared.AtomicUserPanel] with what only the
/// app has: the account that hosts your data (and linking it), AI credits, the
/// web app's profile, storage and settings pages, and the full device card.
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

  /// Tells the app that another account was signed in, so it shows that
  /// account's drives.
  final VoidCallback? onSignedInAsOther;

  /// Test seam for the sign-in screen the "Sign in to another account" entry
  /// opens (it gets the callback for the signed-in app).
  @visibleForTesting
  final Widget Function(VoidCallback onLoggedIn)? signInPage;

  const SyncScreen({
    super.key,
    this.onSignedInAsOther,
    this.signInPage,
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

  /// The agent's profile: the native editor when the backend can save it,
  /// else the agent's own page in the embedded web renderer.
  Future<void> _openProfile(BuildContext _, shared.AtomicIdentity agent) async {
    final drive = _backend.getActiveDrive();
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
  }

  /// The web app's settings page, like the storage page: in the detail pane
  /// next to the list, else pushed.
  void _openSettings() {
    final drive = _backend.getActiveDrive() ?? '';
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

  /// The login screen's sign-in options, on top of this one. It comes back
  /// with the names of the drives of the account signed in before that came
  /// along. Resolves true when the panel has to reload.
  Future<bool> _signInAsOther(BuildContext context) async {
    final onLoggedIn = widget.onSignedInAsOther ?? () {};
    // Taken before leaving: showing the app as the other account may rebuild
    // this screen, and the line still has to be said.
    final toasts = ToastScope.maybeOf(context);
    final messenger = ScaffoldMessenger.maybeOf(context);
    final brought =
        await Navigator.of(context).push<List<String>>(MaterialPageRoute(
      builder: (_) =>
          widget.signInPage?.call(onLoggedIn) ??
          LoginScreen(switchAccount: true, onLoggedIn: onLoggedIn),
    ));
    if (brought != null && brought.isNotEmpty) {
      final message = broughtAlongMessage(brought);
      if (toasts != null) {
        toasts.show('signed-in-as-other', message, icon: Icons.check);
      } else {
        messenger?.showSnackBar(SnackBar(content: Text(message)));
      }
    }
    return brought != null;
  }

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
      // A tablet's detail pane: a readable column, centred.
      body: LayoutBuilder(
        builder: (context, box) => Padding(
          padding: readableHorizontalPadding(box.maxWidth),
          child: shared.AtomicUserPanel(
            backend: _backend,
            avatarBuilder: (agent, radius) =>
                agentAvatar(agent, radius: radius),
            openProfile: _openProfile,
            signInAsOther: _signInAsOther,
            onSignedOut: () => Navigator.of(context).pop(true),
            onCopied: _copied,
            accountBuilder: (context, info) => _AccountSection(
              backend: _backend,
              info: info,
              loadAccount: widget.loadAccount,
              linkAccount: widget.linkAccount,
              loadCredits: widget.loadCredits,
              portalCookie: widget.portalCookie,
              portalPage: widget.portalPage,
            ),
            thisDeviceBuilder: (context, info) => shared.ThisDeviceCard(
              backend: _backend,
              deviceName: info.deviceName,
              peerId: info.peerId,
              identity: info.agent?.subject,
              driveNames: info.driveNames,
              onRename: info.rename,
              onOpenStorage: _openStorage,
              extraRows: const [_BackgroundActivityRow()],
              loadExpanded: () async =>
                  (await SharedPreferences.getInstance())
                      .getBool(_storageExpandedKey) ??
                  false,
              saveExpanded: (v) async => (await SharedPreferences.getInstance())
                  .setBool(_storageExpandedKey, v),
            ),
          ),
        ),
      ),
    );
  }

  /// The app's toast, once: a SnackBar shows on every Scaffold of the
  /// messenger, so on a tablet both the sidebar and the page drew it.
  void _copied(BuildContext context, String message) {
    final toasts = ToastScope.maybeOf(context);
    if (toasts == null) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(message)));
      return;
    }
    toasts
      ..clearCooldown('copied')
      ..show('copied', message, icon: Icons.check);
  }
}

/// The account that hosts your data (only when one is linked, or can be): its
/// address, Cloud Vault, Cloud Server and AI credits for the active workspace,
/// and the way to the portal. Reloads when the panel does.
class _AccountSection extends StatefulWidget {
  final shared.AtomicSettingsBackend backend;
  final shared.AtomicUserInfo info;
  final Future<AccountSummary?> Function(String? drive)? loadAccount;
  final Future<void> Function(BuildContext context, String portal)? linkAccount;
  final Future<shared.AtomicAiCredits?> Function()? loadCredits;
  final Future<String?> Function(Uri portal)? portalCookie;
  final Widget Function(ResourceWebView page)? portalPage;

  const _AccountSection({
    required this.backend,
    required this.info,
    this.loadAccount,
    this.linkAccount,
    this.loadCredits,
    this.portalCookie,
    this.portalPage,
  });

  @override
  State<_AccountSection> createState() => _AccountSectionState();
}

class _AccountSectionState extends State<_AccountSection> {
  AccountSummary? _account;
  String? _accountError;

  /// Last known AI credits, kept when a refresh fails (offline).
  shared.AtomicAiCredits? _credits;
  bool _creditsLoading = false;
  bool _creditsFailed = false;

  /// Where the active server is administered, when it is a managed one: the
  /// only place an account can be linked from.
  String? _portal;
  bool _openingPortal = false;

  @override
  void initState() {
    super.initState();
    _loadAccount();
  }

  @override
  void didUpdateWidget(_AccountSection old) {
    super.didUpdateWidget(old);
    if (old.info.loads != widget.info.loads) _loadAccount();
  }

  /// Where an account can be linked: the portal a known server reports for
  /// itself (the active one first). A self-hosted server names none, so a
  /// person who never used a hosted account is never offered one.
  Future<String?> _findPortal() async {
    final servers = widget.backend.servers;
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
      account = await (widget.loadAccount ??
          AccountStore.summary)(widget.info.activeDrive);
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

  void _fail(String what, Object e) =>
      shared.showErrorSnack(context, '$what: $e');

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
            deviceName: widget.info.deviceName.isEmpty
                ? 'atomic.place'
                : widget.info.deviceName,
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

  String _driveLabel() => widget.info.driveLabel(widget.info.activeDrive ?? '');

  @override
  Widget build(BuildContext context) {
    final c = shared.syncColors(context);
    if (_account != null || _accountError != null) return _account_(c);
    final portal = _portal;
    return portal == null ? const SizedBox.shrink() : _linkRow(c, portal);
  }

  /// Only for a linked account: address, Cloud Vault and Cloud Server for the
  /// active workspace, and the way to the portal.
  Widget _account_(shared.AppColors c) {
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
        subtitle:
            vault == null ? 'Off for ${_driveLabel()}' : _vaultLine(vault),
      ),
      shared.SyncRow(
        icon: Icons.cloud_outlined,
        title: 'Cloud Server',
        subtitle:
            server == null ? 'Off for ${_driveLabel()}' : _serverLine(server),
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

  Widget _linkRow(shared.AppColors c, String portal) =>
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

/// The line after signing in as another account: which drives of the one
/// before are in this account now.
String broughtAlongMessage(List<String> names) {
  final quoted = [for (final n in names) '"$n"'];
  final list = quoted.length == 1
      ? quoted.single
      : '${quoted.sublist(0, quoted.length - 1).join(', ')} and ${quoted.last}';
  return 'Added to your account: $list.';
}
