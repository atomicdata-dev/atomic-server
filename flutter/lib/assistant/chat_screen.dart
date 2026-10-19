import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import 'assistant_api.dart';
import 'fading_text.dart';
import 'hosted_ai.dart';
import 'hosted_voice.dart';
import 'voice.dart';

/// SharedPreferences key: speak each new answer aloud.
const _readAloudKey = 'chat_read_aloud';

/// SharedPreferences key: the recogniser language the person picked.
const voiceLocaleKey = 'voice_locale';

/// A resource the person attached to a new chat as context.
typedef _Attached = ({
  String subject,
  String title,
  String className,
  String? emoji
});

/// Most characters of one attached resource, and of all of them, sent to the AI.
const _maxItemChars = 4000;
const _maxContextChars = 12000;

/// Most recently opened resources offered in the picker.
const _maxRecent = 6;

/// Most pills in the new-chat context picker.
const _maxPills = 5;

/// A chat: the text of each message, newest at the bottom, and, when an AI is
/// available, a field to write to it. A chat without a [subject] is new: it is
/// created with the first message.
class ChatScreen extends StatefulWidget {
  final AssistantApi api;
  final String? subject;
  final String title;

  /// Speech to text and text to speech; the plugin ones when null, created
  /// only when first used.
  final SpeechInput? speechInput;
  final SpeechOutput? speechOutput;

  /// The account (Whisper) speech to text; made from the linked account's AI
  /// when null.
  final HostedSpeechInput? hostedSpeechInput;

  /// Whether the language sheet lists languages for the account engine.
  final bool accountLanguageHints;

  const ChatScreen({
    super.key,
    required this.api,
    this.subject,
    this.title = '',
    this.speechInput,
    this.speechOutput,
    this.hostedSpeechInput,
    this.accountLanguageHints = hostedLanguageHintSupported,
  });

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> with WidgetsBindingObserver {
  final _input = TextEditingController();
  final _focus = FocusNode();
  String? _chat;
  List<ChatMessage> _messages = const [];
  Object? _loadError;
  bool _loaded = false;

  /// The AI of the linked account, once looked up; null when there is none.
  HostedAi? _ai;
  bool _aiLooked = false;

  /// The answer as it streams in, in the pieces it came in.
  List<(String, DateTime)>? _partial;
  bool _sending = false;
  String? _error;

  /// What the person attached, in the order they picked it; sent to the AI
  /// with every message of this screen, never stored in the chat.
  final List<_Attached> _attached = [];
  final Map<String, String> _attachedText = {};

  /// What the picker offers, once read.
  List<DriveInfo>? _drives;
  List<(String drive, RecentResource)>? _recent;
  bool _pickerRead = false;

  SpeechInput? _inputInst;
  SpeechOutput? _outputInst;
  HostedSpeechInput? _hostedInst;
  bool _listening = false;

  /// The recording was ended and the account is transcribing it.
  bool _transcribing = false;

  /// The current listen is on the account engine, not the device's.
  bool _hostedActive = false;

  /// A one-line note about the engine, e.g. why the device's was used.
  String? _voiceNote;

  /// True from the tap until the recogniser is really listening; the
  /// permission prompt pauses the app and must not cancel that.
  bool _starting = false;
  double _level = 0;

  /// The last input levels, newest last, for the waveform.
  final List<double> _levels = [];
  bool _readAloud = false;

  /// Bumped whenever listening starts or is cancelled, so late results of an
  /// older session are ignored.
  int _listenSession = 0;

  /// The language tag shown on the mic while listening, e.g. `nl-NL`.
  String? _activeLocale;

  /// Text recognised in the current listen.
  bool _heard = false;

  /// Listening ended without any words: a gentle hint instead of silence.
  bool _noSpeechHint = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _inputInst = widget.speechInput;
    _hostedInst = widget.hostedSpeechInput;
    _input.addListener(_inputChanged);
    _outputInst = widget.speechOutput;
    _loadReadAloud();
    _chat = widget.subject;
    _readMessages();
    _lookUpAi();
    if (_chat == null) _readPicker();
  }

  bool _hadText = false;

  void _inputChanged() {
    final has = _input.text.trim().isNotEmpty;
    if (has == _hadText && !_noSpeechHint) return;
    _hadText = has;
    // Typing clears the hint.
    if (mounted) setState(() => _noSpeechHint = false);
  }

  @override
  void dispose() {
    _input.removeListener(_inputChanged);
    WidgetsBinding.instance.removeObserver(this);
    _listenSession++;
    _inputInst?.stop();
    if (widget.hostedSpeechInput == null) {
      _hostedInst?.dispose();
    } else {
      _hostedInst?.cancel();
    }
    _outputInst?.stop();
    _focus.dispose();
    _input.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed && !_starting) _stopListening();
  }

  Future<void> _loadReadAloud() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final on = prefs.getBool(_readAloudKey) ?? false;
      if (mounted && on != _readAloud) setState(() => _readAloud = on);
    } catch (_) {}
  }

  Future<void> _toggleReadAloud() async {
    final on = !_readAloud;
    setState(() => _readAloud = on);
    if (!on) _outputInst?.stop();
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool(_readAloudKey, on);
    } catch (_) {}
  }

  HostedSpeechInput get _hosted =>
      _hostedInst ??= HostedSpeechInput.forAccount(_ai);

  /// Throws away an account recording or transcription under way.
  void _cancelHosted() {
    if (!_hostedActive || !(_listening || _transcribing)) return;
    _listenSession++;
    _listening = false;
    _starting = false;
    _transcribing = false;
    _level = 0;
    _hosted.cancel();
    if (mounted) setState(() {});
  }

  /// Ends listening; what was heard so far stays in the field.
  void _stopListening() {
    if (!_listening) return;
    if (_hostedActive) {
      // Still waiting for the microphone: nothing to transcribe.
      if (_starting) return _cancelHosted();
      // The recording is sent for transcription; its text arrives later.
      final session = _listenSession;
      _listening = false;
      _level = 0;
      _transcribing = true;
      final hosted = _hosted;
      hosted.stop().whenComplete(() {
        if (mounted && session == _listenSession && _transcribing) {
          setState(() => _transcribing = false);
        }
      });
      if (mounted) setState(() {});
      return;
    }
    _listenSession++;
    _listening = false;
    _starting = false;
    _level = 0;
    if (!_heard) _noSpeechHint = true;
    _inputInst?.stop();
    if (mounted) setState(() {});
  }

  Future<SharedPreferences?> _prefs() async {
    try {
      return await SharedPreferences.getInstance();
    } catch (_) {
      return null;
    }
  }

  /// Which engine to use now: the chosen one, else the account's when it can
  /// be used. [note] says why the device's was used instead of the chosen one.
  Future<({String engine, String? note})> _resolveEngine(
      SharedPreferences? prefs) async {
    final chosen = prefs?.getString(voiceEngineKey);
    if (chosen == voiceEngineDevice) {
      return (engine: voiceEngineDevice, note: null);
    }
    HostedAvailability avail;
    try {
      avail = await _hosted.availability();
    } catch (_) {
      avail =
          const HostedAvailability.unavailable('Could not reach your account.');
    }
    if (avail.ok) return (engine: voiceEngineAccount, note: null);
    if (chosen == null) return (engine: voiceEngineDevice, note: null);
    return (
      engine: voiceEngineDevice,
      note: '${avail.reason ?? 'The account is not available.'} '
          'Using this device instead.',
    );
  }

  Future<void> _toggleListening() async {
    if (_listening) {
      _stopListening();
      return;
    }
    if (_transcribing) return;
    // Typed text stays; what is heard is appended after it.
    String baseOf(String typed) =>
        typed.isEmpty || typed.endsWith(' ') || typed.endsWith('\n')
            ? typed
            : '$typed ';
    final session = ++_listenSession;
    _hostedActive = false;
    setState(() {
      _noSpeechHint = false;
      _voiceNote = null;
      _heard = false;
      _listening = true;
      _starting = true;
      _level = 0;
      _levels.clear();
      _error = null;
    });
    // Speech from the speaker would be heard as input.
    _outputInst?.stop();
    final prefs = await _prefs();
    final choice = await _resolveEngine(prefs);
    final hosted = choice.engine == voiceEngineAccount;
    if (!mounted || session != _listenSession) return;
    _hostedActive = hosted;
    final SpeechInput input =
        hosted ? _hosted : (_inputInst ??= PluginSpeechInput());
    String? localeId;
    if (hosted) {
      if (widget.accountLanguageHints) {
        localeId = prefs?.getString(voiceLanguageKey);
      }
    } else {
      localeId = prefs?.getString(voiceLocaleKey);
      localeId ??= await input.systemLocale();
      if (!mounted || session != _listenSession) return;
    }
    final base = baseOf(_input.text);
    setState(() {
      _voiceNote = choice.note;
      _activeLocale = hosted ? 'whisper' : localeId?.replaceAll('_', '-');
    });
    if (hosted) {
      _hosted.onTranscribing = (on) {
        if (!mounted || session != _listenSession) return;
        setState(() {
          _listening = false;
          _starting = false;
          _level = 0;
          _transcribing = on;
        });
      };
    }
    final ok = await input.start(
      localeId: localeId,
      onText: (text, isFinal) {
        if (!mounted || session != _listenSession) return;
        if (text.isNotEmpty) _heard = true;
        // Account text arrives once, at the end: after whatever was typed
        // meanwhile.
        final at = hosted ? baseOf(_input.text) : base;
        _input.value = TextEditingValue(
          text: '$at$text',
          selection: TextSelection.collapsed(offset: at.length + text.length),
        );
        if (isFinal) {
          setState(() {
            _listening = false;
            _transcribing = false;
            _level = 0;
            _noSpeechHint = !_heard;
          });
        } else if (_noSpeechHint) {
          setState(() => _noSpeechHint = false);
        }
      },
      onError: (e) {
        if (!mounted || session != _listenSession) return;
        // The account engine gives plain messages, the device codes.
        final message = hosted ? e : voiceErrorMessage(e);
        setState(() {
          _listening = false;
          _transcribing = false;
          _level = 0;
          // Hearing nothing is a normal end, not a failure.
          if (message != null) {
            _error = message;
          } else if (!_heard) {
            _noSpeechHint = true;
          }
        });
      },
      onLevel: (level) {
        if (!mounted || session != _listenSession || !_listening) return;
        setState(() {
          _level = level.clamp(0.0, 1.0);
          _levels.add(_level);
          if (_levels.length > 24) _levels.removeAt(0);
        });
      },
    );
    if (session == _listenSession) _starting = false;
    if (!mounted || session != _listenSession) {
      if (ok && hosted) _hosted.cancel();
      return;
    }
    if (!ok) {
      setState(() {
        _listening = false;
        _level = 0;
        _error = 'Voice input is not available. Allow the microphone in '
            'system settings.';
      });
    }
  }

  /// Long-press on the mic: pick the engine and its language.
  Future<void> _openVoiceSheet() async {
    _stopListening();
    final input = _inputInst ??= PluginSpeechInput();
    final all = await input.locales();
    final system = await input.systemLocale();
    final prefs = await _prefs();
    if (!mounted) return;
    final availability = _hosted.availability().catchError(
          (Object _) => const HostedAvailability.unavailable(
              'Could not reach your account.'),
        );
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (_) => _VoiceSheet(
        locales: all,
        systemId: system,
        currentLocale: prefs?.getString(voiceLocaleKey) ?? system,
        availability: availability,
        engine: prefs?.getString(voiceEngineKey),
        language: prefs?.getString(voiceLanguageKey),
        languageHints: widget.accountLanguageHints,
      ),
    );
    if (mounted) setState(() => _noSpeechHint = false);
  }

  Future<void> _readMessages() async {
    final chat = _chat;
    if (chat == null) {
      setState(() => _loaded = true);
      return;
    }
    try {
      final messages = await widget.api.messages(chat);
      if (mounted) {
        setState(() {
          _messages = messages;
          _loaded = true;
          _loadError = null;
        });
        if (messages.isEmpty) _readPicker();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _loadError = e;
          _loaded = true;
        });
      }
    }
  }

  /// A new chat is for writing: the field gets the cursor as soon as it can.
  void _focusInput() {
    if (widget.subject != null) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && _ai != null && _ai!.available && _ai!.consent) {
        _focus.requestFocus();
      }
    });
  }

  /// The drives and the recently opened resources of all of them, newest
  /// first, for the picker.
  Future<void> _readPicker() async {
    if (_pickerRead) return;
    _pickerRead = true;
    List<DriveInfo> drives;
    try {
      drives = await widget.api.drives();
    } catch (_) {
      drives = const [];
    }
    final lists = await Future.wait([
      for (final d in drives)
        widget.api.recentResources(d.subject).then(
              (list) => [for (final r in list) (d.subject, r)],
              onError: (Object _) => <(String, RecentResource)>[],
            ),
    ]);
    final recent = [for (final l in lists) ...l]
      ..sort((a, b) => b.$2.openedAt.compareTo(a.$2.openedAt));
    if (mounted) {
      setState(() {
        _drives = drives;
        _recent = recent.take(_maxRecent).toList();
      });
    }
  }

  void _toggle(_Attached item) {
    setState(() {
      final at = _attached.indexWhere((a) => a.subject == item.subject);
      if (at >= 0) {
        _attached.removeAt(at);
      } else {
        _attached.add(item);
      }
    });
  }

  /// The text of what was attached, to go ahead of the history; null when
  /// nothing was.
  Future<String?> _contextText() async {
    if (_attached.isEmpty) return null;
    final parts = <String>[];
    for (final a in List.of(_attached)) {
      var text = _attachedText[a.subject];
      if (text == null) {
        try {
          text =
              await widget.api.resourceText(a.subject, maxChars: _maxItemChars);
        } catch (_) {
          continue;
        }
        _attachedText[a.subject] = text;
      }
      if (text.length > _maxItemChars) text = text.substring(0, _maxItemChars);
      parts.add('${a.title} (${a.className})\n$text');
    }
    if (parts.isEmpty) return null;
    final all = 'The user attached these resources as context:\n\n'
        '${parts.join('\n\n')}';
    return all.length > _maxContextChars
        ? all.substring(0, _maxContextChars)
        : all;
  }

  Future<void> _lookUpAi() async {
    try {
      final ai = await widget.api.hostedAi();
      if (mounted) {
        setState(() {
          _ai = ai;
          _aiLooked = true;
        });
        _focusInput();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _aiLooked = true;
          _error = '$e';
        });
      }
    }
  }

  Future<void> _enableAi() async {
    try {
      await _ai!.enable();
      if (mounted) {
        setState(() => _error = null);
        _focusInput();
      }
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    }
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    final ai = _ai;
    if (text.isEmpty || ai == null || _sending || _transcribing) return;
    // A recording for the account is dropped, not sent along.
    _cancelHosted();
    _stopListening();
    _outputInst?.stop();
    _input.clear();
    final asked = [
      ..._messages,
      (id: 'new', role: 'user', text: text, createdAt: 0),
    ];
    setState(() {
      _sending = true;
      _error = null;
      _messages = asked;
      _partial = [];
    });
    try {
      // The chat exists from the first message on, named after it.
      final chat = _chat ??= await widget.api.newChat(
        text.length > 40 ? '${text.substring(0, 40)}…' : text,
      );
      await widget.api.addMessage(chat, 'user', text);
      var answer = '';
      final context = await _contextText();
      await for (final delta in ai.answer(asked, context: context)) {
        answer += delta;
        if (mounted) {
          setState(() => _partial = [..._partial!, (delta, DateTime.now())]);
        }
      }
      if (answer.trim().isNotEmpty) {
        await widget.api.addMessage(chat, 'assistant', answer);
      }
      await _readMessages();
      if (_readAloud && mounted && answer.trim().isNotEmpty) {
        (_outputInst ??= PluginSpeechOutput()).speak(answer);
      }
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) {
        setState(() {
          _sending = false;
          _partial = null;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppBar(
        backgroundColor: c.bgBody,
        title: Text(
          widget.title.isEmpty
              ? (_chat == null ? 'New chat' : 'Untitled chat')
              : widget.title,
        ),
        actions: [
          IconButton(
            tooltip: _readAloud ? 'Stop reading aloud' : 'Read answers aloud',
            onPressed: _toggleReadAloud,
            icon: Icon(_readAloud ? Icons.volume_up : Icons.volume_off),
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(child: _list(c)),
          _composer(c),
        ],
      ),
    );
  }

  Widget _list(AppColors c) {
    if (_loadError != null) {
      return Center(
        child: Text('$_loadError', style: TextStyle(color: c.alert)),
      );
    }
    if (!_loaded) return const Center(child: CircularProgressIndicator());
    final shown = [
      ..._messages,
      if (_partial != null)
        (id: 'partial', role: 'assistant', text: '', createdAt: 0),
    ];
    if (shown.isEmpty) return _picker(c);
    return ListView.builder(
      reverse: true,
      padding: const EdgeInsets.all(16),
      itemCount: shown.length,
      itemBuilder: (context, i) {
        final m = shown[shown.length - 1 - i];
        final mine = m.role == 'user';
        return Align(
          alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
          child: Container(
            margin: const EdgeInsets.symmetric(vertical: 4),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.85,
            ),
            decoration: BoxDecoration(
              color: mine ? c.mainSelectedBg : c.bg1,
              borderRadius: BorderRadius.circular(9),
            ),
            child: m.id == 'partial'
                ? (_partial!.isEmpty
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : FadingText(
                        chunks: _partial!,
                        style: TextStyle(color: c.textPrimary),
                      ))
                : SelectableText(
                    m.text,
                    style: TextStyle(
                      color: mine ? c.mainSelectedFg : c.textPrimary,
                    ),
                  ),
          ),
        );
      },
    );
  }

  /// A small pill; the selected one is told apart by colour, not an icon.
  Widget _pill(AppColors c, _Attached item) {
    final on = _attached.any((a) => a.subject == item.subject);
    final title =
        item.title.length > 22 ? '${item.title.substring(0, 21)}…' : item.title;
    final label = item.emoji == null ? title : '${item.emoji} $title';
    return Material(
      color: on ? c.main.withValues(alpha: 0.12) : c.bg1,
      shape: StadiumBorder(
        side: BorderSide(
          color: on ? c.main.withValues(alpha: 0.6) : c.bg1,
        ),
      ),
      child: InkWell(
        customBorder: const StadiumBorder(),
        onTap: () => _toggle(item),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 5),
          child: Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 12,
              color: on ? c.main : c.textSecondary,
            ),
          ),
        ),
      ),
    );
  }

  /// What a new chat shows instead of messages: a few resources to give the
  /// AI as context (up to 5: two drives, then the latest opened). Optional;
  /// the chat starts without if nothing is picked.
  Widget _picker(AppColors c) {
    final drives = _drives ?? const <DriveInfo>[];
    final recent = _recent ?? const <(String, RecentResource)>[];
    final options = <_Attached>[
      for (final d in drives.take(2))
        (
          subject: d.subject,
          title: d.name.isEmpty ? 'Untitled drive' : d.name,
          className: 'Drive',
          emoji: d.emoji,
        ),
    ];
    for (final (_, r) in recent) {
      if (options.length >= _maxPills) break;
      if (options.any((o) => o.subject == r.subject)) continue;
      options.add((
        subject: r.subject,
        title: r.title.isEmpty ? 'Untitled' : r.title,
        className: r.className,
        emoji: r.emoji,
      ));
    }
    if (options.isEmpty) return const SizedBox.shrink();
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Add context?',
              style: TextStyle(color: c.textSecondary, fontSize: 12),
            ),
            const SizedBox(height: 8),
            Wrap(
              alignment: WrapAlignment.center,
              spacing: 6,
              runSpacing: 8,
              children: [for (final o in options) _pill(c, o)],
            ),
          ],
        ),
      ),
    );
  }

  /// The attached resources, each removable.
  Widget _chips() => Align(
        alignment: Alignment.centerLeft,
        child: Padding(
          padding: const EdgeInsets.only(bottom: 6),
          child: Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              for (final a in _attached)
                Chip(
                  label: Text(a.title, overflow: TextOverflow.ellipsis),
                  visualDensity: VisualDensity.compact,
                  onDeleted: () => _toggle(a),
                  deleteButtonTooltipMessage: 'Remove ${a.title}',
                ),
            ],
          ),
        ),
      );

  /// The way to write, when there is an AI to write to; otherwise one line
  /// saying so.
  Widget _composer(AppColors c) {
    final ai = _ai;
    Widget hint(String text) => Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Text(
            text,
            style: TextStyle(color: c.textSecondary, fontSize: 13),
            textAlign: TextAlign.center,
          ),
        );
    // While the AI is looked up, the field is there already, switched off:
    // the messages above stay where they are when the answer lands.
    if (_aiLooked && ai == null) {
      return SafeArea(child: hint(_error ?? 'No AI is set up on this device.'));
    }
    if (ai != null && !ai.available) {
      return SafeArea(child: hint('Included AI is not available.'));
    }
    if (ai != null && !ai.consent) {
      return SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Messages you send here are processed by your account '
                "provider's AI, and use your account's credits.",
                style: TextStyle(color: c.textSecondary, fontSize: 13),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              FilledButton(
                onPressed: _enableAi,
                child: const Text('Turn on AI'),
              ),
              if (_error != null)
                Text(_error!, style: TextStyle(color: c.alert, fontSize: 12)),
            ],
          ),
        ),
      );
    }
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 4, 12, 12),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Text(
                  _error!,
                  style: TextStyle(color: c.alert, fontSize: 12),
                ),
              ),
            if (_attached.isNotEmpty && _messages.isNotEmpty) _chips(),
            if (_listening) _Waveform(levels: _levels),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _input,
                    focusNode: _focus,
                    minLines: 1,
                    maxLines: 5,
                    textInputAction: TextInputAction.send,
                    // Stays enabled while a reply streams (`_send` ignores a
                    // second send), and submitting keeps focus: the keyboard
                    // stays open for the next message.
                    enabled: ai != null,
                    readOnly: _transcribing,
                    onEditingComplete: () {},
                    onSubmitted: (_) => _send(),
                    decoration: InputDecoration(
                      hintText: 'Message',
                      filled: true,
                      fillColor: c.bg1,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(9),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),
                ),
                _MicButton(
                  listening: _listening,
                  level: _level,
                  locale: _activeLocale,
                  transcribing: _transcribing,
                  onLongPress:
                      ai == null || _transcribing ? null : _openVoiceSheet,
                  onPressed: ai == null ? null : _toggleListening,
                ),
                IconButton.filled(
                  tooltip: 'Send',
                  onPressed:
                      _sending || _transcribing || ai == null || !_hadText
                          ? null
                          : _send,
                  icon: const Icon(Icons.arrow_upward),
                ),
              ],
            ),
            if (_voiceNote != null)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                  _voiceNote!,
                  key: const Key('voice-note'),
                  style: TextStyle(color: c.textSecondary, fontSize: 12),
                ),
              ),
            if (_noSpeechHint && !_listening)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                  "Didn't hear anything. Check the language (long-press the "
                  'mic) and try again.',
                  key: const Key('voice-hint'),
                  style: TextStyle(color: c.textSecondary, fontSize: 12),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// Short wording for a recogniser error; null when it is not a failure (the
/// recogniser just heard nothing usable).
String? voiceErrorMessage(String code) {
  switch (code) {
    case 'error_no_match':
    case 'error_speech_timeout':
      return null;
    case 'error_network':
    case 'error_network_timeout':
    case 'error_server':
      return 'No internet connection for speech recognition.';
    case 'error_permission':
    case 'error_insufficient_permissions':
      return 'Microphone permission is needed.';
    case 'error_recognizer_busy':
    case 'error_busy':
      return 'Voice input is busy, try again.';
    default:
      return 'Voice input failed.';
  }
}

/// The mic button; while listening a soft ring behind the stop icon follows
/// the input level and breathes gently when it is quiet.
class _MicButton extends StatefulWidget {
  final bool listening;
  final double level;
  final VoidCallback? onPressed;
  final VoidCallback? onLongPress;
  final String? locale;
  final bool transcribing;

  const _MicButton({
    required this.listening,
    required this.level,
    required this.onPressed,
    this.onLongPress,
    this.locale,
    this.transcribing = false,
  });

  @override
  State<_MicButton> createState() => _MicButtonState();
}

class _MicButtonState extends State<_MicButton>
    with SingleTickerProviderStateMixin {
  late final AnimationController _breath;

  @override
  void initState() {
    super.initState();
    _breath = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    if (widget.listening) _breath.repeat(reverse: true);
  }

  @override
  void didUpdateWidget(_MicButton old) {
    super.didUpdateWidget(old);
    if (widget.listening && !_breath.isAnimating) {
      _breath.repeat(reverse: true);
    } else if (!widget.listening && _breath.isAnimating) {
      _breath.stop();
      _breath.value = 0;
    }
  }

  @override
  void dispose() {
    _breath.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    const area = 48.0;
    return SizedBox(
      width: area,
      height: area,
      child: Stack(
        alignment: Alignment.center,
        clipBehavior: Clip.none,
        children: [
          if (widget.listening)
            AnimatedBuilder(
              animation: _breath,
              builder: (context, _) {
                // Between 1.0x and 1.6x; the idle breath stays under 1.15x.
                final strength = widget.level > _breath.value * 0.25
                    ? widget.level
                    : _breath.value * 0.25;
                final size = area * (1 + 0.6 * strength.clamp(0.0, 1.0));
                return IgnorePointer(
                  child: OverflowBox(
                    maxWidth: area * 2,
                    maxHeight: area * 2,
                    child: AnimatedContainer(
                      key: const Key('mic-level-ring'),
                      duration: const Duration(milliseconds: 100),
                      width: size,
                      height: size,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: c.main.withValues(alpha: 0.18),
                      ),
                    ),
                  ),
                );
              },
            ),
          if (widget.transcribing)
            const SizedBox(
              width: 22,
              height: 22,
              child: CircularProgressIndicator(
                key: Key('mic-transcribing'),
                strokeWidth: 2.5,
              ),
            )
          else
            Tooltip(
              message:
                  widget.listening ? 'Stop voice input' : 'Start voice input',
              // Long-press picks the language instead.
              triggerMode: TooltipTriggerMode.manual,
              child: GestureDetector(
                onLongPress: widget.onLongPress,
                child: IconButton(
                  onPressed: widget.onPressed,
                  color: widget.listening ? c.main : null,
                  icon: Icon(widget.listening ? Icons.stop : Icons.mic),
                ),
              ),
            ),
          if (widget.transcribing ||
              (widget.listening && widget.locale != null))
            Positioned(
              bottom: 1,
              child: IgnorePointer(
                child: Text(
                  widget.transcribing ? 'transcribing…' : widget.locale!,
                  key: const Key('mic-locale'),
                  style: TextStyle(color: c.textSecondary, fontSize: 9),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

/// A compact strip of thin rounded bars, one per recent input level.
class _Waveform extends StatelessWidget {
  final List<double> levels;

  const _Waveform({required this.levels});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    const count = 24;
    const maxH = 28.0;
    const minH = 3.0;
    // Pad on the left so the newest bar is always at the right.
    final shown = [
      for (var i = 0; i < count - levels.length; i++) 0.0,
      ...levels,
    ];
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: SizedBox(
        key: const Key('mic-waveform'),
        height: maxH,
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            for (final l in shown)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 1.5),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 100),
                  width: 3,
                  height: minH + (maxH - minH) * l.clamp(0.0, 1.0),
                  decoration: BoxDecoration(
                    color: c.main,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// The voice input sheet: which engine transcribes, and its language. The
/// device engine lists the recogniser's languages (suggested ones first, with
/// a search field); the account engine detects the language by itself, with
/// an optional hint when the server takes one. Choices are saved as they are
/// made.
class _VoiceSheet extends StatefulWidget {
  final List<SpeechLocale> locales;
  final String? systemId;
  final String? currentLocale;
  final Future<HostedAvailability> availability;
  final String? engine;
  final String? language;
  final bool languageHints;

  const _VoiceSheet({
    required this.locales,
    required this.systemId,
    required this.currentLocale,
    required this.availability,
    required this.engine,
    required this.language,
    required this.languageHints,
  });

  @override
  State<_VoiceSheet> createState() => _VoiceSheetState();
}

class _VoiceSheetState extends State<_VoiceSheet> {
  String _query = '';
  HostedAvailability? _avail;
  String? _engine;
  String? _language;

  @override
  void initState() {
    super.initState();
    _engine = widget.engine;
    _language = widget.language;
    widget.availability.then((a) {
      if (mounted) setState(() => _avail = a);
    });
  }

  /// The engine in effect: the chosen one, else the account's when usable;
  /// the account's is never in effect while unusable.
  String get _effective {
    if (_engine == voiceEngineDevice) return voiceEngineDevice;
    return _avail?.ok == true ? voiceEngineAccount : voiceEngineDevice;
  }

  Future<void> _save(String key, String? value) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      if (value == null) {
        await prefs.remove(key);
      } else {
        await prefs.setString(key, value);
      }
    } catch (_) {}
  }

  Future<void> _pickEngine(String engine) async {
    setState(() => _engine = engine);
    await _save(voiceEngineKey, engine);
  }

  Future<void> _pickLocale(String id) async {
    await _save(voiceLocaleKey, id);
    if (mounted) Navigator.pop(context);
  }

  Future<void> _pickLanguage(String? code) async {
    await _save(voiceLanguageKey, code);
    if (mounted) Navigator.pop(context);
  }

  bool _match(SpeechLocale l) {
    final q = _query.trim().toLowerCase();
    return q.isEmpty ||
        l.name.toLowerCase().contains(q) ||
        l.id.toLowerCase().contains(q);
  }

  Widget _heading(String t) {
    final c = context.appColors;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 2),
      child: Text(t, style: TextStyle(color: c.textSecondary, fontSize: 12)),
    );
  }

  Widget _engineTile({
    required Key key,
    required String engine,
    required String title,
    required String subtitle,
    String? reason,
    bool enabled = true,
  }) {
    final c = context.appColors;
    final on = _effective == engine;
    return ListTile(
      key: key,
      dense: true,
      enabled: enabled,
      leading: Icon(
        on ? Icons.radio_button_checked : Icons.radio_button_unchecked,
        color: on ? c.main : null,
      ),
      title: Text(title),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(subtitle),
          if (reason != null)
            Text(reason, style: TextStyle(color: c.alert, fontSize: 12)),
        ],
      ),
      selected: on,
      onTap: enabled ? () => _pickEngine(engine) : null,
    );
  }

  Widget _deviceLanguages() {
    final c = context.appColors;
    final byId = {for (final l in widget.locales) l.id: l};
    final suggested = <SpeechLocale>[];
    for (final id in [widget.systemId, 'nl_NL', 'en_US', 'en_GB']) {
      final l = id == null ? null : byId[id];
      if (l != null && !suggested.contains(l)) suggested.add(l);
    }
    final rest = [
      for (final l in widget.locales)
        if (!suggested.contains(l)) l,
    ]..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    Widget tile(SpeechLocale l) => ListTile(
          dense: true,
          title: Text(l.name),
          subtitle: Text(l.id),
          selected: l.id == widget.currentLocale,
          onTap: () => _pickLocale(l.id),
        );
    final sug = suggested.where(_match).toList();
    final others = rest.where(_match).toList();
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 4, 12, 8),
          child: TextField(
            key: const Key('locale-search'),
            decoration: const InputDecoration(
              hintText: 'Search language',
              prefixIcon: Icon(Icons.search),
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
        Expanded(
          child: widget.locales.isEmpty
              ? Center(
                  child: Text(
                    'No languages available.',
                    style: TextStyle(color: c.textSecondary),
                  ),
                )
              : ListView(children: [
                  if (sug.isNotEmpty) _heading('Suggested'),
                  for (final l in sug) tile(l),
                  if (sug.isNotEmpty && others.isNotEmpty)
                    _heading('All languages'),
                  for (final l in others) tile(l),
                ]),
        ),
      ],
    );
  }

  Widget _accountLanguages() {
    final auto = _language == null || _language!.isEmpty;
    return ListView(children: [
      ListTile(
        key: const Key('language-auto'),
        dense: true,
        title: const Text('Auto-detect'),
        subtitle: widget.languageHints
            ? null
            : const Text('Whisper recognises the language by itself.'),
        selected: auto,
        onTap: () => _pickLanguage(null),
      ),
      if (widget.languageHints)
        for (final (code, name) in hostedLanguages)
          ListTile(
            key: Key('language-$code'),
            dense: true,
            title: Text(name),
            subtitle: Text(code),
            selected: _language == code,
            onTap: () => _pickLanguage(code),
          ),
    ]);
  }

  @override
  Widget build(BuildContext context) {
    final avail = _avail;
    final accountOk = avail?.ok == true;
    return SafeArea(
      child: Padding(
        padding:
            EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
        child: SizedBox(
          height: MediaQuery.sizeOf(context).height * 0.75,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                child: Text('Voice input',
                    style: Theme.of(context).textTheme.titleMedium),
              ),
              _heading('Engine'),
              _engineTile(
                key: const Key('engine-account'),
                engine: voiceEngineAccount,
                title: 'atomic.place account',
                subtitle: 'Whisper, any language, uses credits',
                enabled: accountOk,
                reason: avail == null
                    ? 'Checking your account…'
                    : avail.ok
                        ? null
                        : avail.reason,
              ),
              _engineTile(
                key: const Key('engine-device'),
                engine: voiceEngineDevice,
                title: 'This device',
                subtitle: 'Google speech recognition, free, live words',
              ),
              const Divider(height: 8),
              _heading('Language'),
              Expanded(
                child: _effective == voiceEngineAccount
                    ? _accountLanguages()
                    : _deviceLanguages(),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
