import 'package:atomic_flutter/atomic_flutter.dart'
    show Perf, normalizeServerUrl;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:atomic_chat/atomic_chat.dart' show AtomicWordmark;
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:url_launcher/url_launcher.dart';
import '../atomic/account_store.dart';
import '../atomic/atomic_client.dart';
import '../atomic/session.dart';
import '../theme.dart';
import 'account_link_dialog.dart';
import 'pair_screen.dart';

class LoginScreen extends StatefulWidget {
  final VoidCallback onLoggedIn;

  /// Signs in with the person's atomic.place account and returns the identity
  /// its backup holds; null when cancelled. Replaceable in tests.
  final Future<shared.AtomicRecoveredIdentity?> Function(BuildContext context)?
      accountSignIn;

  /// The account client for the default sign-in, and how it opens a page in
  /// the system browser. Replaceable in tests.
  final shared.AtomicAccountClient Function()? accountClient;
  final Future<void> Function(Uri url)? openBrowser;

  const LoginScreen(
      {super.key,
      required this.onLoggedIn,
      this.accountSignIn,
      this.accountClient,
      this.openBrowser});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

enum _Step { loading, welcome, createAgent, showSecret, signIn, needsSync }

class _LoginScreenState extends State<LoginScreen> {
  _Step _step = _Step.loading;
  final _nameController = TextEditingController(text: '');
  final _secretController = TextEditingController();
  final _shownSecretController = TextEditingController();
  final _accountNameController = TextEditingController(text: 'atomic.place');
  // A secret is hidden by default — it is a password. A reveal toggle lets
  // someone check a value they typed or pasted.
  bool _obscureSecret = true;
  final _serverController = TextEditingController();
  String? _error;
  bool _busy = false;

  // After setup
  String? _generatedSecret;
  bool _peerSyncAttempted = false;

  /// What the sync step is doing right now, while it is busy.
  String? _status;

  /// What the server lookup did, for the error text.
  String _lookup = '';

  @override
  void initState() {
    super.initState();
    _tryAutoLogin();
  }

  @override
  void dispose() {
    _nameController.dispose();
    _secretController.dispose();
    _accountNameController.dispose();
    _shownSecretController.dispose();
    _serverController.dispose();
    super.dispose();
  }

  /// Normalized, so `localhost:9883` works as typed — the same rule the
  /// server settings use. Empty stays empty: no hub is a valid choice.
  String get _serverOrigin => normalizeServerUrl(_serverController.text);

  /// Open WS sync to the server (primary path for multi-device).
  Future<void> _startNetworking(String driveSubject,
      {String? serverUrl}) async {
    final origin =
        (serverUrl != null && serverUrl.isNotEmpty) ? serverUrl : _serverOrigin;
    // A local-only identity (Get Started without a server) has nothing to
    // connect to; asking anyway failed on `ws:///ws`.
    if (origin.isEmpty) return;
    try {
      await AtomicClient.openWsSync(origin);
    } catch (e) {
      debugPrint('WS sync failed (offline?): $e');
    }
  }

  /// True when the active drive exists in the local DB (name property readable).
  Future<bool> _driveReady() async {
    final drive = AtomicClient.getActiveDrive();
    if (drive == null) return false;
    try {
      final name = await AtomicClient.getProperty(
          drive, 'https://atomicdata.dev/properties/name');
      return name.isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  Future<void> _tryAutoLogin() async {
    try {
      final session = await AtomicSession.loadEarly();
      Perf.once('session loaded');
      if (session == null || session.secret.isEmpty) {
        setState(() => _step = _Step.welcome);
        return;
      }
      if (session.serverUrl.isNotEmpty) {
        _serverController.text = session.serverUrl;
      }

      final status = await AtomicClient.resumeSession(
        serverUrl: session.serverUrl,
        secret: session.secret,
        drive: session.drive,
      );

      final drive = AtomicClient.getActiveDrive();
      if (drive != null) {
        await AtomicSession.saveDrive(drive);
      }

      if (status == 'ok' && await _driveReady()) {
        widget.onLoggedIn();
        return;
      }

      setState(() {
        _step = _Step.needsSync;
        _peerSyncAttempted = false;
      });
      return;
    } catch (e) {
      debugPrint('Auto-login failed: $e');
    }

    setState(() => _step = _Step.welcome);
  }

  /// Re-run boot sync: optional WS hub (if configured) + Iroh known peers / discover.
  /// Look for the workspace on the other devices — the slow part sign-in used
  /// to block on. It runs here instead, on a screen built to wait: Iroh
  /// discovery (pkarr + known peers) that can take tens of seconds, or land the
  /// moment a paired device answers.
  Future<void> _retryPeerSync() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      // A drive that is not here yet may live on a server that announced it in
      // pkarr: one HTTPS round trip, so it goes before the device search.
      final wanted = AtomicClient.getActiveDrive();
      if (wanted != null && !await _driveReady()) {
        setState(() => _status = 'Looking for the server your drive lives on…');
        String? found;
        try {
          found = await AtomicClient.discoverHomeServer(wanted);
        } catch (e) {
          debugPrint('Home server lookup failed: $e');
        }
        // Said on screen if the devices fail to help either: it is the answer
        // to "why is nothing here".
        _lookup = AtomicClient.discoveryLog.join('\n');
        if (found != null) {
          // Remember where it lives, so the next start reconnects there.
          await AtomicSession.setActiveServer(found);
          await AtomicSession.saveDrive(wanted);
          if (await _driveReady()) {
            widget.onLoggedIn();
            return;
          }
        }
      }
      if (mounted) setState(() => _status = 'Looking for your devices…');
      final report = await AtomicClient.syncConnectivityNow();

      final drive = AtomicClient.getActiveDrive();
      if (drive != null) {
        await AtomicSession.saveDrive(drive);
      }

      if (drive != null && await _driveReady()) {
        widget.onLoggedIn();

        return;
      }

      setState(() => _error = [
            if (_lookup.isNotEmpty) _lookup,
            report.imported > 0 || report.livePeers > 0
                ? 'Synced, but your workspace isn’t here yet — try again'
                : report.message,
          ].join('\n'));
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          _status = null;
        });
      }
    }
  }

  // ── Step: Create Agent ──────────────────────────────────────────────

  Future<void> _doSetup() async {
    final name = _nameController.text.trim();
    if (name.isEmpty) {
      setState(() => _error = 'Enter a name');
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final result = await AtomicClient.setup(name);
      await AtomicSession.save(
        serverUrl: _serverOrigin,
        secret: result.agentSecret,
        drive: result.driveSubject,
      );

      await _startNetworking(result.driveSubject, serverUrl: _serverOrigin);

      setState(() {
        _generatedSecret = result.agentSecret;
        _step = _Step.showSecret;
        _busy = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _busy = false;
      });
    }
  }

  // ── Step: Sign In ───────────────────────────────────────────────────

  /// Paste the clipboard into the field and sign in, in one tap — the secret
  /// almost always comes from another device's clipboard, so pasting is the
  /// action, not a step before it.
  Future<void> _pasteSecretAndSignIn() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final pasted = data?.text?.trim() ?? '';

    if (pasted.isEmpty) {
      setState(() => _error = 'Nothing to paste');

      return;
    }

    _secretController.text = pasted;
    await _doSignIn();
  }

  Future<void> _doSignIn() async {
    final secret = _secretController.text.trim();
    if (secret.isEmpty) {
      setState(() => _error = 'Paste your secret');
      return;
    }
    await _signInWithSecret(secret);
  }

  /// "Sign in with atomic.place": the account sign-in (a code approved on a
  /// device or in the browser), then the identity its backup holds, which
  /// signs the app in exactly like a pasted secret.
  Future<void> _signInWithAccount() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    shared.AtomicRecoveredIdentity? identity;
    try {
      identity = await (widget.accountSignIn ?? _defaultAccountSignIn)(context);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = '$e'.replaceFirst('Bad state: ', '');
          // The account is linked but its secret can't be recovered here:
          // the paste field is the way on.
          if (e is shared.AtomicNoAssistedRecovery) _step = _Step.signIn;
        });
      }
      return;
    }
    if (identity == null) {
      if (mounted) setState(() => _busy = false);
      return;
    }
    await _signInWithSecret(identity.secret, drive: identity.drive);
  }

  Future<shared.AtomicRecoveredIdentity?> _defaultAccountSignIn(
      BuildContext context) async {
    final client = widget.accountClient?.call() ??
        shared.AtomicAccountClient(AccountStore.defaultPortal);
    try {
      final linked = await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (_) => AccountLinkDialog(
          client: client,
          deviceName: 'atomic.place',
          save: AccountStore.save,
          // The browser unlocks the backup, which it can for passkey and
          // recovery-code backups too, and sends the secret back sealed.
          handback: true,
          openInBrowser: widget.openBrowser ??
              (url) async {
                await launchUrl(url, mode: LaunchMode.externalApplication);
              },
        ),
      );
      if (linked != true) return null;
      try {
        // An older portal approves without a sealed identity: fall back to
        // the server-assisted backup.
        return client.takeHandedBackIdentity() ??
            await client.recoverIdentity();
      } catch (_) {
        // Without the identity the account session is of no use here, and
        // keeping it made a failed sign-in look half done.
        await AccountStore.clear();
        rethrow;
      }
    } finally {
      client.close();
    }
  }

  Future<void> _signInWithSecret(String secret, {String? drive}) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final stored = await AtomicSession.save(
        serverUrl: _serverOrigin,
        secret: secret,
        drive: drive,
      );
      if (!stored && mounted) {
        ScaffoldMessenger.maybeOf(context)?.showSnackBar(
          const SnackBar(
            content: Text('Couldn\u2019t save your sign-in on this device; '
                'you\u2019ll need to sign in again next time'),
          ),
        );
      }

      final status = await AtomicClient.resumeSession(
        serverUrl: _serverOrigin,
        secret: secret,
        drive: drive,
      );

      final activeDrive = AtomicClient.getActiveDrive();
      if (activeDrive != null) {
        await AtomicSession.saveDrive(activeDrive);
      }

      // The secret was accepted: let the password manager offer to save it.
      TextInput.finishAutofillContext();

      if (status == 'ok' && await _driveReady()) {
        widget.onLoggedIn();
      } else {
        setState(() {
          _busy = false;
          _step = _Step.needsSync;
          _peerSyncAttempted = false;
        });
      }
    } catch (e) {
      debugPrint('Sign in: $e');
      setState(() {
        _error = signInError(e);
        _busy = false;
      });
    }
  }

  // ── Build ───────────────────────────────────────────────────────────

  /// The steps the system back leaves for the welcome screen, as their own
  /// back arrows do; elsewhere back leaves the app.
  static const _backToWelcome = {
    _Step.createAgent,
    _Step.signIn,
    _Step.needsSync,
  };

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return PopScope(
      canPop: !_backToWelcome.contains(_step),
      onPopInvokedWithResult: (didPop, _) {
        if (didPop || _busy) return;
        setState(() {
          _step = _Step.welcome;
          _error = null;
        });
      },
      child: _scaffold(c),
    );
  }

  Widget _scaffold(AppColors c) {
    return Scaffold(
      backgroundColor: c.pageBg,
      body: SafeArea(
          child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: AnimatedSwitcher(
              duration: const Duration(milliseconds: 200),
              child: _buildStep(c),
            ),
          ),
        ),
      )),
    );
  }

  Widget _buildStep(AppColors c) {
    switch (_step) {
      case _Step.loading:
        return const Center(
            key: ValueKey('loading'), child: CircularProgressIndicator());
      case _Step.welcome:
        return _buildWelcome(c);
      case _Step.createAgent:
        return _buildCreateAgent(c);
      case _Step.showSecret:
        return _buildShowSecret(c);
      case _Step.signIn:
        return _buildSignIn(c);
      case _Step.needsSync:
        return _buildNeedsSync(c);
    }
  }

  // ── Welcome ─────────────────────────────────────────────────────────

  Widget _buildWelcome(AppColors c) {
    return Column(
      key: const ValueKey('welcome'),
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Center(
          child: AtomicWordmark(height: 40, alignment: Alignment.center),
        ),
        const SizedBox(height: 16),
        const SizedBox(height: 8),
        Text(
          'Your data stays on this device.\nSync with others when you choose to.',
          style: TextStyle(fontSize: 14, color: c.iconDisabled),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 40),
        ElevatedButton(
          onPressed: () => setState(() {
            _step = _Step.createAgent;
            _error = null;
          }),
          style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 14)),
          child: const Text('Get Started'),
        ),
        const SizedBox(height: 12),
        OutlinedButton(
          onPressed: () => setState(() {
            _step = _Step.signIn;
            _error = null;
          }),
          style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 14)),
          child: const Text('I have a secret — Sign In'),
        ),
        const SizedBox(height: 12),
        OutlinedButton(
          key: const ValueKey('sign-in-with-account'),
          onPressed: _busy ? null : _signInWithAccount,
          style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 14)),
          child: const Text('Sign in with atomic.place'),
        ),
        _errorWidget(),
      ],
    );
  }

  // ── Create Agent ────────────────────────────────────────────────────

  Widget _buildCreateAgent(AppColors c) {
    return Column(
      key: const ValueKey('create'),
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            IconButton(
              icon: const Icon(Icons.arrow_back),
              onPressed: () => setState(() {
                _step = _Step.welcome;
                _error = null;
              }),
            ),
            const Text('Create your identity',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
          ],
        ),
        const SizedBox(height: 8),
        Text(
          'This creates a cryptographic identity and a personal drive to store your data.',
          style: TextStyle(fontSize: 13, color: c.iconDisabled),
        ),
        const SizedBox(height: 24),
        // No sync address here: a new identity has no data anywhere to go and
        // find, so asking where it syncs — before asking your name — is a
        // question about plumbing at the one moment there is nothing to plumb.
        // Settings has it, for when there is.
        TextField(
          controller: _nameController,
          decoration: const InputDecoration(
            labelText: 'Your name',
            border: OutlineInputBorder(),
            isDense: true,
          ),
          autofocus: true,
          textInputAction: TextInputAction.go,
          onSubmitted: (_) => _doSetup(),
        ),
        const SizedBox(height: 16),
        ElevatedButton(
          onPressed: _busy ? null : _doSetup,
          style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 14)),
          child: _busy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2))
              : const Text('Create'),
        ),
        _errorWidget(),
      ],
    );
  }

  // ── Show Secret ─────────────────────────────────────────────────────

  Widget _buildShowSecret(AppColors c) {
    return Column(
      key: const ValueKey('secret'),
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Icon(Icons.check_circle, color: Colors.green, size: 48),
        const SizedBox(height: 16),
        const Text(
          'You\'re all set!',
          style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: c.warningBg,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: c.warningBorder),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Save this secret: it is the only way to sign in as you on another device.',
                style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
              ),
              const SizedBox(height: 12),
              // A read-only password field, so a password manager can save the
              // new secret (with the fixed account name) when this is left.
              AutofillGroup(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Offstage(
                      child: TextField(
                        key: const ValueKey('secret-username'),
                        controller: _accountNameController,
                        readOnly: true,
                        autofillHints: const [AutofillHints.username],
                      ),
                    ),
                    TextField(
                      key: const ValueKey('secret-password'),
                      controller: _shownSecretController
                        ..text = _generatedSecret ?? '',
                      readOnly: true,
                      maxLines: null,
                      autofillHints: const [AutofillHints.newPassword],
                      style: const TextStyle(
                          fontSize: 11, fontFamily: 'monospace'),
                      decoration: const InputDecoration.collapsed(hintText: ''),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: _generatedSecret!));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Copied to clipboard')),
                  );
                },
                icon: const Icon(Icons.copy, size: 16),
                label: const Text('Copy secret'),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        ElevatedButton(
          onPressed: () {
            // Leaving the form commits the autofill context: the manager
            // offers to save the new secret.
            TextInput.finishAutofillContext();
            widget.onLoggedIn();
          },
          style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 14)),
          child: const Text('Continue'),
        ),
      ],
    );
  }

  // ── Sign In ─────────────────────────────────────────────────────────

  Widget _buildSignIn(AppColors c) {
    return AutofillGroup(
        key: const ValueKey('signin'),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.arrow_back),
                  onPressed: () => setState(() {
                    _step = _Step.welcome;
                    _error = null;
                  }),
                ),
                const Text('Sign in',
                    style:
                        TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              'Paste your secret to restore your identity.',
              style: TextStyle(fontSize: 13, color: c.iconDisabled),
            ),
            const SizedBox(height: 24),
            // Signing in restores who you are. Where your data is, is the next
            // screen's question — and only if it turns out not to be here, which
            // is the moment it can be asked with something to point at (`needsSync`
            // offers pairing). Asking up front asks everyone, before anyone has the
            // problem, and asks it as an address when the answer is usually a
            // device you can just scan.
            // Password managers pair a credential with an account name: a fixed,
            // read-only one, so the secret is saved and offered as "atomic.place".
            TextField(
              key: const ValueKey('signin-username'),
              controller: _accountNameController,
              readOnly: true,
              autofillHints: const [AutofillHints.username],
              decoration: const InputDecoration(
                labelText: 'Account',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const ValueKey('signin-secret'),
              controller: _secretController,
              obscureText: _obscureSecret,
              autofillHints: const [AutofillHints.password],
              enableSuggestions: false,
              autocorrect: false,
              keyboardType: TextInputType.visiblePassword,
              autofocus: true,
              // Enter submits — a secret is one line, pasted or not.
              onSubmitted: (_) => _busy ? null : _doSignIn(),
              decoration: InputDecoration(
                labelText: 'Your secret',
                border: const OutlineInputBorder(),
                isDense: true,
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscureSecret ? Icons.visibility : Icons.visibility_off,
                    size: 20,
                  ),
                  tooltip: _obscureSecret ? 'Show' : 'Hide',
                  onPressed: () =>
                      setState(() => _obscureSecret = !_obscureSecret),
                ),
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _busy ? null : _doSignIn,
                    style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 14)),
                    child: _busy
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2))
                        : const Text('Sign In'),
                  ),
                ),
                const SizedBox(width: 8),
                // Paste-and-go: the secret lives on another device's clipboard,
                // so one tap pastes it and signs in.
                OutlinedButton.icon(
                  onPressed: _busy ? null : _pasteSecretAndSignIn,
                  icon: const Icon(Icons.content_paste, size: 18),
                  label: const Text('Paste'),
                  style: OutlinedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(
                          vertical: 14, horizontal: 12)),
                ),
              ],
            ),
            _errorWidget(),
          ],
        ));
  }

  // ── Needs Sync ──────────────────────────────────────────────────────

  Widget _buildNeedsSync(AppColors c) {
    if (!_peerSyncAttempted && !_busy) {
      _peerSyncAttempted = true;
      WidgetsBinding.instance.addPostFrameCallback((_) => _retryPeerSync());
    }
    return Column(
      key: const ValueKey('needsSync'),
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Icon(Icons.sync_problem, size: 48, color: Colors.orange),
        const SizedBox(height: 16),
        const Text(
          'Sync your drive',
          style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 12),
        Text(
          'This device does not have your drive yet. '
          'We look for other devices on the network, or you can pair with QR or a node ID.',
          style: TextStyle(fontSize: 14, color: c.iconDisabled),
          textAlign: TextAlign.center,
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          Text(_error!,
              style: TextStyle(fontSize: 13, color: c.alert),
              textAlign: TextAlign.center),
        ],
        const SizedBox(height: 24),
        ElevatedButton.icon(
          icon: _busy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.sync),
          label: Text(
              _busy ? (_status ?? 'Looking for your devices…') : 'Try again'),
          style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 14)),
          onPressed: _busy ? null : _retryPeerSync,
        ),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          icon: const Icon(Icons.qr_code_scanner),
          label: const Text('Pair with QR'),
          style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 14)),
          onPressed: () => _pairThenCheck(null),
        ),
        const SizedBox(height: 4),
        TextButton.icon(
          icon: const Icon(Icons.content_paste),
          label: const Text('Paste node ID'),
          onPressed: _pasteNodeId,
        ),
        const SizedBox(height: 12),
        OutlinedButton(
          onPressed: () => setState(() {
            _step = _Step.welcome;
          }),
          child: const Text('Back'),
        ),
      ],
    );
  }

  /// Pair with [nodeId] (or scan a code when null), then continue when the
  /// drive arrived.
  Future<void> _pairThenCheck(String? nodeId) async {
    await PairScreen.show(context, nodeId: nodeId);
    final drive = AtomicClient.getActiveDrive();
    if (drive != null) {
      try {
        final name = await AtomicClient.getProperty(
            drive, 'https://atomicdata.dev/properties/name');
        if (name.isNotEmpty) {
          widget.onLoggedIn();
          return;
        }
      } catch (_) {}
    }
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Drive not synced yet — try again')),
      );
    }
  }

  /// For when no camera can see the other device's code: its node ID, copied
  /// from its Sync page, pasted here. Prefilled from the clipboard.
  Future<void> _pasteNodeId() async {
    final clip = (await Clipboard.getData(Clipboard.kTextPlain))?.text ?? '';
    if (!mounted) return;
    final controller = TextEditingController(
        text: PairScreen.parsePeerInfo(clip) != null ? clip.trim() : '');
    final nodeId = await showDialog<String>(
      context: context,
      builder: (context) {
        String? error;
        return StatefulBuilder(
          builder: (context, setDialogState) {
            void submit() {
              final info = PairScreen.parsePeerInfo(controller.text);
              if (info == null) {
                setDialogState(() => error = 'Not a node ID');
                return;
              }
              Navigator.of(context).pop(info.nodeId);
            }

            return AlertDialog(
              title: const Text('Paste node ID'),
              content: TextField(
                controller: controller,
                autofocus: true,
                decoration: InputDecoration(
                  hintText: 'did:ad:node:…',
                  errorText: error,
                ),
                onSubmitted: (_) => submit(),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('Cancel'),
                ),
                TextButton(onPressed: submit, child: const Text('Connect')),
              ],
            );
          },
        );
      },
    );
    controller.dispose();
    if (nodeId != null && mounted) await _pairThenCheck(nodeId);
  }

  Widget _errorWidget() {
    if (_error == null) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(top: 16),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: Theme.of(context).extension<AppColors>()?.errorBg ??
              Colors.red.shade50,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(_error!,
            style: TextStyle(
                color: Theme.of(context).extension<AppColors>()?.alert ??
                    Colors.red,
                fontSize: 13)),
      ),
    );
  }
}

/// What a failed sign-in with a secret says: a secret that is not one (cut
/// short, a word, something else on the clipboard) gets a sentence a person
/// can act on, not the decoder's "Not valid Base64. Invalid last symbol 116,
/// offset 9."; anything else as it came.
String signInError(Object error) {
  if (error is PlatformException) return keychainErrorMessage(error);
  final text = '$error';
  final notASecret = RegExp(r'Invalid key|Base64|base64|Invalid secret|decode',
          caseSensitive: false)
      .hasMatch(text);
  if (notASecret) {
    return 'That is not a secret. A secret is the long code you saved when '
        'you made your identity; on a device that is signed in, Sync → '
        'Copy secret key gives it.';
  }
  return text.replaceFirst('Bad state: ', '');
}
