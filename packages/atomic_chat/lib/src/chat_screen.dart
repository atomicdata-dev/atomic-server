import 'package:atomic_flutter/atomic_flutter.dart' show ErrorText, ClickCursor;
import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, Perf;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show ScrollCacheExtent;
import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'dart:math' as math;

import 'app_top_bar.dart';
import 'home_sections.dart' show HomeSection;
import 'package:shared_preferences/shared_preferences.dart';

import 'models.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'ai_tools.dart';
import 'web_tool_bridge.dart';
import 'attachments.dart';
import 'resource_row.dart';
import 'chat_parts.dart';
import 'chat_window.dart';
import 'scroll_to_bottom_button.dart';
import 'markdown_view.dart';
import 'chat_bubbles.dart';
import 'chat_text_styles.dart';
import 'tool_step.dart';
import 'toast.dart';
import 'native_views.dart';
import 'package:url_launcher/url_launcher.dart';
import 'hosted_ai.dart';
import 'hosted_voice.dart';
import 'voice.dart';
import 'list_and_field.dart';

/// SharedPreferences key: speak each new answer aloud.

/// SharedPreferences key: the recogniser language the person picked.
const voiceLocaleKey = 'voice_locale';

/// A resource the person attached to a new chat as context.
typedef _Attached = ContextResource;

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
///
/// In [voiceMode] the chat is spoken, turn by turn: it listens as soon as the
/// AI is there (with the chosen speech engine), sends what was heard when the
/// speaker pauses, reads the answer aloud (whatever the read-aloud setting)
/// and listens again when it is done. Stop ends the loop; leaving the screen
/// or the app does too, and so does an error (which is shown).
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

  /// A spoken chat: listen, send, speak the answer, listen again.
  final bool voiceMode;

  /// Gets photos and files to attach; [defaultAttachmentPicker] when null.
  final AttachmentPicker? attachmentPicker;

  /// The tools the model may call; the assistant's read-only tools
  /// ([assistantTools]) when null. Only an AI that reports tool calls gets
  /// them.
  final List<AiTool>? tools;

  /// The web app's AI tools and system prompt (see [WebToolBridge]); the
  /// device's [defaultToolBridge] when null and [tools] is not given.
  final WebToolBridge? toolBridge;

  /// The bridge for a device without one given: a hidden web view of the
  /// embedded page on a phone or tablet, none elsewhere (tests, desktop).
  /// `drive` gives the subject of the drive the tools work on.
  static WebToolBridge? Function(
          AssistantApi api, Future<String> Function() drive) defaultToolBridge =
      (api, drive) => !kIsWeb && (Platform.isAndroid || Platform.isIOS)
          ? WebViewToolBridge(api: api, drive: drive)
          : null;

  const ChatScreen({
    super.key,
    required this.api,
    this.subject,
    this.title = '',
    this.speechInput,
    this.speechOutput,
    this.hostedSpeechInput,
    this.accountLanguageHints = hostedLanguageHintSupported,
    this.voiceMode = false,
    this.tools,
    this.toolBridge,
    this.attachmentPicker,
  });

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

/// An answer being written, owned by no screen: it outlives the screen that
/// asked, and a screen opened on the chat meanwhile attaches to it.
class _LiveRun {
  /// The answer's parts so far.
  final parts = ValueNotifier<List<ChatPart>>(const []);

  /// Completes when the answer is written to the store (or given up).
  final _done = Completer<void>();
  Future<void> get done => _done.future;
}

/// The runs of the chats being answered, by chat subject.
final _liveRuns = <String, _LiveRun>{};

class _ChatScreenState extends State<ChatScreen> with WidgetsBindingObserver {
  final _input = TextEditingController();
  final _focus = FocusNode();
  String? _chat;

  /// The window of the chat on screen: its newest messages, older ones read
  /// as the list scrolls up, and the ones written here added at the end
  /// (see [ChatWindow]). A chat can be very long; only this is held.
  late final ChatWindow<ChatEntry> _window = ChatWindow(
    readPage: (before, limit) =>
        widget.api.chatEntriesPage(_chat!, before: before, limit: limit),
    // Only this screen writes the chat while it is open: nothing is polled;
    // this reads the newest pages back after a far scroll up dropped them.
    readAfter: (after, limit) =>
        widget.api.chatEntriesAfter(_chat!, after, limit: limit),
    idOf: (m) => m.id,
    onOlderPage: (ms, n) => Perf.span('chat older page $n', ms),
  );
  late final _keeper = ChatScrollKeeper(_window);

  // Following an answer as it streams in (see [_settle]): the list follows
  // the growing answer at the bottom while the answer's top is in view;
  // once the answer fills the screen its top is held there, so it can be
  // read from its start. A person who scrolls takes over.
  final _listKey = GlobalKey();
  final _sentKey = GlobalKey();
  final _answerKey = GlobalKey();

  /// The question just sent and the answer to it (`partial` while it
  /// streams), or on opening the chat its newest answer.
  String? _sentId;
  String? _answerId;

  /// Following the answer at the bottom.
  bool _follow = false;

  /// The answer's top reached the top of the list: held there.
  bool _pinned = false;

  /// Room below the answer so the question can sit at the top of the list
  /// with the answer growing under it.
  double _spacer = 0;
  double? _answerHeight;
  bool _settleQueued = false;
  List<ChatEntry> get _messages => _window.items;
  Object? get _loadError => _window.error;
  bool _noChatYet = false;
  bool get _loaded => _window.loaded || _noChatYet;

  /// The bridge made by [ChatScreen.defaultToolBridge], kept for the screen.
  WebToolBridge? _ownBridge;
  bool _bridgeMade = false;

  /// The web app's tools for this chat: the one given, else the device's own
  /// (made once). None when [ChatScreen.tools] is given.
  WebToolBridge? _toolBridge() {
    if (widget.toolBridge != null) return widget.toolBridge;
    if (widget.tools != null) return null;
    if (!_bridgeMade) {
      _bridgeMade = true;
      // The drive the person is in, when the shell knows it.
      final shell = ShellScope.maybeOf(context);
      _ownBridge = ChatScreen.defaultToolBridge(widget.api, () async {
        final current = shell?.drive.value ?? '';
        if (current.isNotEmpty) return current;
        try {
          final drives = visibleDrives(await widget.api.drives());
          return drives.isEmpty ? '' : drives.first.subject;
        } catch (_) {
          return '';
        }
      });
    }
    return _ownBridge;
  }

  /// The AI of the linked account, once looked up; null when there is none.
  HostedAi? _ai;
  bool _aiLooked = false;

  /// The answer's parts as they stream in; null when none is coming.
  List<ChatPart>? _partial;

  /// Shows what arrived since the screen last showed the answer: at most
  /// about 30 times a second, not on every piece.
  Timer? _flush;
  bool _sending = false;
  String? _error;

  /// What the person attached, in the order they picked it; sent to the AI
  /// with every message of this screen, never stored in the chat.
  final List<_Attached> _attached = [];
  final Map<String, String> _attachedText = {};

  /// Resources added with the attach button (not one of the pills): their
  /// chips show also on a chat that is still empty.
  final Set<String> _fromDrive = {};

  /// Photos and files to go with the next message.
  final List<FilePart> _files = [];

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

  /// Bumped whenever listening starts or is cancelled, so late results of an
  /// older session are ignored.
  int _listenSession = 0;

  /// The language tag shown on the mic while listening, e.g. `nl-NL`.
  String? _activeLocale;

  /// Text recognised in the current listen.
  bool _heard = false;

  /// Listening ended without any words: a gentle hint instead of silence.
  bool _noSpeechHint = false;

  /// "Stop and send" is waiting for the final transcript; blocks a second tap.
  bool _finalising = false;

  /// Completed by the recogniser's final result while finalising.
  Completer<void>? _finalWaiter;

  /// The account engine was stopped by "Stop and send": its text is sent as
  /// soon as the transcription arrives.
  bool _sendWhenTranscribed = false;

  /// How long "Stop and send" waits for the final result before sending the
  /// latest partial one.
  static const _finalWait = Duration(milliseconds: 600);

  /// Voice mode's turn-by-turn loop is running.
  bool _voiceLoop = false;

  /// The answer is being read aloud by the voice loop.
  bool _speaking = false;

  /// The listen session whose end the voice loop handled already.
  int _voiceHandled = -1;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _inputInst = widget.speechInput;
    _hostedInst = widget.hostedSpeechInput;
    _input.addListener(_inputChanged);
    _outputInst = widget.speechOutput;
    _chat = widget.subject;
    _readMessages();
    _lookUpAi();
    if (_chat == null) _readPicker();
    // New on a new chat that is still empty: its field gets the cursor.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      final route = ModalRoute.of(context);
      if (route != null) {
        ShellScope.maybeOf(context)?.onReselect(route, _focusInput);
      }
    });
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
    // An answer on its way is NOT cancelled by leaving the screen: it runs to
    // its end, is saved, and a screen opened meanwhile shows it live (see
    // [_LiveRun]). Cancelling here lost the whole answer.
    if (_sending) {
      _ownBridgeOpenUntilDone = true;
    } else {
      _flush?.cancel();
      _sub?.cancel();
      final own = _ownBridge;
      if (own is WebViewToolBridge) own.close();
    }
    _window.removeListener(_windowChanged);
    _window.dispose();
    _keeper.dispose();
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

  bool _ownBridgeOpenUntilDone = false;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed || _starting) return;
    // The voice loop ends with the app in the background: nothing is sent.
    if (_voiceLoop || _speaking) return _stopVoice();
    _stopListening();
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
  void _stopListening({bool stopInput = true}) {
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
    if (stopInput) _inputInst?.stop();
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

  /// Stops dictation and sends what was recognised right away, as if the
  /// normal send button was pressed. The words so far (the latest partial
  /// result when the final one does not come in time) are in the field.
  Future<void> _stopAndSend() async {
    if (!_listening || _finalising || _voiceLoop) return;
    if (_hostedActive) {
      // Nothing recorded yet: nothing to send.
      if (_starting) return _cancelHosted();
      // The account transcribes after the stop; the final result sends.
      _sendWhenTranscribed = true;
      _stopListening();
      return;
    }
    final session = _listenSession;
    final waiter = _finalWaiter = Completer<void>();
    setState(() => _finalising = true);
    _inputInst?.stop();
    await waiter.future.timeout(_finalWait, onTimeout: () {});
    _finalWaiter = null;
    if (!mounted) return;
    setState(() => _finalising = false);
    if (session != _listenSession) return;
    _stopListening(stopInput: false);
    if (_input.text.trim().isEmpty && _files.isEmpty) {
      setState(() => _noSpeechHint = true);
      return;
    }
    _send();
  }

  Future<void> _toggleListening() async {
    _sendWhenTranscribed = false;
    if (_listening) {
      _stopListening();
      // In the voice loop, stopping means "done talking": the device's words
      // are sent now (the account's once transcribed).
      if (_voiceLoop && !_hostedActive) _voiceTurnEnded(_listenSession);
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
          final waiter = _finalWaiter;
          if (waiter != null && !waiter.isCompleted) waiter.complete();
          if (_sendWhenTranscribed) {
            _sendWhenTranscribed = false;
            if (_input.text.trim().isNotEmpty) _send();
          }
          if (_voiceLoop) _voiceTurnEnded(session);
        } else if (_noSpeechHint) {
          setState(() => _noSpeechHint = false);
        }
      },
      onError: (e) {
        if (!mounted || session != _listenSession) return;
        _sendWhenTranscribed = false;
        final waiter = _finalWaiter;
        if (waiter != null && !waiter.isCompleted) waiter.complete();
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
        if (!_voiceLoop) return;
        if (message != null) {
          // An error ends the loop; the message stays.
          setState(() => _voiceLoop = false);
        } else {
          _voiceTurnEnded(session);
        }
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
        _voiceLoop = false;
        _error = 'Voice input is not available. Allow the microphone in '
            'system settings.';
      });
    }
  }

  /// Voice mode: starts (or resumes) the loop with a listen.
  void _startVoice() {
    if (!mounted || _listening || _transcribing || _sending) return;
    setState(() {
      _voiceLoop = true;
      _error = null;
    });
    _toggleListening();
  }

  /// Voice mode: a listen ended. What was heard is sent; nothing heard pauses
  /// the loop (the hint says so, Talk resumes it).
  void _voiceTurnEnded(int session) {
    if (_voiceHandled == session || !_voiceLoop || !mounted) return;
    _voiceHandled = session;
    if (_input.text.trim().isNotEmpty) {
      _send();
    } else {
      setState(() => _voiceLoop = false);
    }
  }

  /// Voice mode: reads [answer] aloud, then listens again.
  Future<void> _speakThenListen(String answer) async {
    if (answer.trim().isNotEmpty) {
      setState(() => _speaking = true);
      try {
        await (_outputInst ??= PluginSpeechOutput()).speak(answer);
      } catch (_) {}
      if (!mounted) return;
      setState(() => _speaking = false);
    }
    if (_voiceLoop) _toggleListening();
  }

  /// Ends the voice loop: listening is dropped (nothing is sent) and reading
  /// aloud stops.
  void _stopVoice() {
    _listenSession++;
    if (_sending) _stopAnswer();
    if (_hostedActive && (_listening || _transcribing)) _hosted.cancel();
    if (_listening && !_hostedActive) _inputInst?.stop();
    _outputInst?.stop();
    _voiceLoop = false;
    _speaking = false;
    _listening = false;
    _starting = false;
    _transcribing = false;
    _level = 0;
    if (mounted) setState(() {});
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

  /// Since the screen was made, for the `chat data` / `chat painted` marks.
  final Stopwatch _opened = Stopwatch()..start();

  void _windowChanged() {
    if (mounted) setState(() {});
  }

  Future<void> _readMessages() async {
    _window.addListener(_windowChanged);
    final chat = _chat;
    if (chat == null) {
      setState(() => _noChatYet = true);
      return;
    }
    await _window.open();
    if (!mounted || _window.error != null) return;
    final live = _liveRuns[chat];
    if (live != null && !_sending) _followRun(live);
    final messages = _window.items;
    // Back in a chat whose newest answer is longer than the screen: open at
    // its start, not at its end.
    if (messages.isNotEmpty && messages.last.role == 'assistant') {
      setState(() => _answerId = messages.last.id);
      WidgetsBinding.instance.addPostFrameCallback((_) => _showAnswerStart());
    }
    Perf.span('chat data ${messages.length}', _opened.elapsedMilliseconds);
    WidgetsBinding.instance.addPostFrameCallback((_) => Perf.span(
        'chat painted ${messages.length}', _opened.elapsedMilliseconds));
    if (messages.isEmpty) _readPicker();
  }

  /// Shows an answer that is still being written by an earlier screen of this
  /// chat; when it is saved the chat is read again.
  void _followRun(_LiveRun live) {
    void show() {
      if (mounted) setState(() => _partial = List.of(live.parts.value));
    }

    setState(() {
      _sending = true;
      _partial = List.of(live.parts.value);
      _answerId = 'partial';
      _follow = true;
    });
    live.parts.addListener(show);
    live.done.whenComplete(() async {
      live.parts.removeListener(show);
      if (!mounted) return;
      await _window.open();
      if (!mounted) return;
      setState(() {
        _sending = false;
        _partial = null;
        final all = _window.items;
        if (all.isNotEmpty && all.last.role == 'assistant') {
          _answerId = all.last.id;
        }
      });
    });
  }

  /// The run this screen started.
  _LiveRun? _live;

  /// The list's box and the top line answers are held at (below the
  /// list's padding), in global coordinates.
  (RenderBox, double)? _listBox() {
    final list = _listKey.currentContext?.findRenderObject();
    if (list is! RenderBox || !list.hasSize || !list.attached) return null;
    return (list, list.localToGlobal(Offset.zero).dy + 16);
  }

  RenderBox? _boxOf(GlobalKey key) {
    final box = key.currentContext?.findRenderObject();
    return box is RenderBox && box.hasSize && box.attached ? box : null;
  }

  /// Scroll so the answer's top is at the top of the list, when it is
  /// above it (an answer taller than the screen).
  void _showAnswerStart() {
    final list = _listBox();
    final answer = _boxOf(_answerKey);
    if (list == null || answer == null || !_keeper.controller.hasClients) {
      return;
    }
    final top = answer.localToGlobal(Offset.zero).dy;
    if (top < list.$2 - 0.5) {
      final pos = _keeper.controller.position;
      pos.jumpTo(math.min(pos.maxScrollExtent, pos.pixels + list.$2 - top));
    }
  }

  void _queueSettle() {
    if (_settleQueued) return;
    _settleQueued = true;
    WidgetsBinding.instance.addPostFrameCallback((_) => _settle());
  }

  /// After each frame while an answer streams in: make room below it so the
  /// question sits at the top; follow it at the bottom while its top is in
  /// view; then hold its top there. When the person scrolled away (or the
  /// top is held), what is on screen stays put as the answer grows (in an
  /// upside-down list a growing last message pushes everything up).
  void _settle() {
    _settleQueued = false;
    if (!mounted || !_keeper.controller.hasClients) return;
    final list = _listBox();
    final answer = _boxOf(_answerKey);
    if (list == null || answer == null) return;
    final pos = _keeper.controller.position;
    final h = answer.size.height;
    final grew = _answerHeight == null ? 0.0 : h - _answerHeight!;
    _answerHeight = h;
    if (_follow && !_pinned) {
      final sent = _boxOf(_sentKey);
      if (sent != null && pos.pixels <= 0.5) {
        final span = answer.localToGlobal(Offset(0, h)).dy -
            sent.localToGlobal(Offset.zero).dy;
        final want = math.max(0.0, list.$1.size.height - 32 - span);
        if ((want - _spacer).abs() > 0.5) {
          setState(() => _spacer = want);
          return;
        }
      }
      final top = answer.localToGlobal(Offset.zero).dy;
      if (top < list.$2 - 0.5) {
        _pinned = true;
        pos.jumpTo(pos.pixels + list.$2 - top);
      }
    } else if (grew.abs() > 0.01 && pos.pixels > 0.5) {
      pos.jumpTo(math.min(pos.maxScrollExtent, pos.pixels + grew));
    }
  }

  /// A drag by the person ends following the answer.
  bool _onScrollStart(ScrollStartNotification n) {
    if (n.dragDetails != null) _follow = false;
    return false;
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
        // Warm at open: boot the hidden page and read its tools and prompt
        // now, so the first answer does not wait for them.
        if (ai != null && ai.supportsTools) {
          final bridge = _toolBridge();
          if (bridge != null) ai.warmWeb(bridge);
        }
        if (widget.voiceMode) {
          if (ai != null && ai.available && ai.consent) _startVoice();
        } else {
          _focusInput();
        }
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
        widget.voiceMode ? _startVoice() : _focusInput();
      }
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    }
  }

  /// Local writes run one after another (the user message before the answer)
  /// but never hold up the model request or the screen.
  Future<void> _persistTail = Future.value();
  int _localId = 0;

  ToastController? _toasts;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _toasts = ToastScope.maybeOf(context);
  }

  /// Backoff between the tries of a failing write.
  @visibleForTesting
  static List<Duration> saveBackoff = const [
    Duration(milliseconds: 500),
    Duration(seconds: 2),
    Duration(seconds: 6),
  ];

  /// Runs a write, again after a pause when it fails: a write that fails
  /// quietly lost the answer. The person is told, with a retry.
  void _persist(String label, Future<void> Function() job) {
    _persistTail = _persistTail.then((_) async {
      final sw = Stopwatch()..start();
      Object? failure;
      for (var attempt = 0; attempt <= saveBackoff.length; attempt++) {
        try {
          await job();
          failure = null;
          break;
        } catch (e) {
          failure = e;
          debugPrint('[chat] persist $label failed (try ${attempt + 1}): $e');
          if (attempt == 0) {
            _toasts?.show('chat-save', "Couldn't save the answer, retrying",
                severity: ToastSeverity.error);
          }
          if (attempt < saveBackoff.length) {
            await Future<void>.delayed(saveBackoff[attempt]);
          }
        }
      }
      final toasts = _toasts;
      if (failure == null) {
        toasts?.resolve('chat-save');
      } else {
        final error = failure;
        toasts?.dismiss('chat-save');
        toasts?.show('chat-save', "Couldn't save the $label",
            severity: ToastSeverity.error,
            actionLabel: 'Retry',
            duration: const Duration(seconds: 15),
            onAction: () => _persist(label, job));
        if (mounted) setState(() => _error = '$error');
      }
      debugPrint('[chat] persist $label took ${sw.elapsedMilliseconds}ms');
    });
  }

  StreamSubscription<AiEvent>? _sub;
  Completer<void>? _streamDone;

  /// Stop writing the reply: the request is cancelled and what came so far
  /// stays as the answer (nothing is kept when it is empty).
  void _stopAnswer() {
    _sub?.cancel();
    _sub = null;
    final done = _streamDone;
    if (done != null && !done.isCompleted) done.complete();
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    final ai = _ai;
    if ((text.isEmpty && _files.isEmpty) ||
        ai == null ||
        _sending ||
        _transcribing) {
      return;
    }
    // A recording for the account is dropped, not sent along.
    _cancelHosted();
    _stopListening();
    _outputInst?.stop();
    _input.clear();
    final sw = Stopwatch()..start();
    void lap(String what) =>
        debugPrint('[ai-perf] +${sw.elapsedMilliseconds}ms $what');
    final userParts = <ChatPart>[
      if (text.isNotEmpty) TextPart(text),
      ..._files,
    ];
    _files.clear();
    final userMessage = ChatEntry(
      id: 'local-${_localId++}',
      role: 'user',
      createdAt: DateTime.now().millisecondsSinceEpoch,
      parts: userParts,
      context: List.of(_attached),
    );
    final name = text.isNotEmpty
        ? text
        : (userParts.whereType<FilePart>().first.filename ?? 'Attachment');
    _window.add(userMessage);
    // What the model reads: the window (the newest messages at least); the
    // AI cuts a long one to its latest part.
    final asked = _window.items;
    if (_keeper.controller.hasClients) _keeper.controller.jumpTo(0);
    setState(() {
      _sending = true;
      _error = null;
      _partial = [];
      // The question goes to the top, the answer grows below it.
      _sentId = userMessage.id;
      _answerId = 'partial';
      _follow = true;
      _pinned = false;
      _answerHeight = null;
    });
    // Written in: New makes another chat from now on, also while the chat
    // itself is still being created.
    if (_chat == null) _noLongerNew();
    // The run belongs to the app, not to this screen (see [_LiveRun]).
    final live = _live = _LiveRun();
    if (_chat != null) _liveRuns[_chat!] = live;
    // The user message is saved in the background; the chat exists from the
    // first message on, named after it.
    _persist('user message', () async {
      final isNew = _chat == null;
      final chat = _chat ??= await widget.api.newChat(
        name.length > 40 ? '${name.substring(0, 40)}…' : name,
      );
      if (isNew) _noLongerNew();
      _liveRuns[chat] ??= live;
      await widget.api.addEntry(chat, 'user', userParts);
    });
    String? spoken;
    // The answer's parts as they arrive: text, and tool calls in between.
    final parts = <ChatPart>[];
    var stopped = false;
    try {
      final context = await _contextText();
      lap('context ready');
      final done = _streamDone = Completer<void>();
      var first = true;
      final tools = ai.supportsTools
          ? (widget.tools ?? assistantTools(widget.api))
          : null;
      final bridge = ai.supportsTools ? _toolBridge() : null;
      _sub = ai
          .run(asked,
              context: context, tools: tools ?? const [], bridge: bridge)
          .listen(
        (event) {
          if (first) {
            first = false;
            lap('first event');
          }
          switch (event) {
            case AiTextDelta(:final text):
              if (parts.isNotEmpty && parts.last is TextPart) {
                parts.last = TextPart((parts.last as TextPart).text + text);
              } else {
                parts.add(TextPart(text));
              }
              _showLater(parts);
            case AiNotice(:final text):
              parts.add(TextPart('_${text}_\n\n'));
              _showNow(parts);
            case AiToolStarted(:final part):
              parts.add(part);
              _showNow(parts);
            case AiToolFinished(:final part):
              final at = parts.indexWhere(
                  (p) => p is ToolPart && p.toolCallId == part.toolCallId);
              at < 0 ? parts.add(part) : parts[at] = part;
              _showNow(parts);
          }
        },
        onError: (Object e, StackTrace st) {
          if (!done.isCompleted) done.completeError(e, st);
        },
        onDone: () {
          if (!done.isCompleted) done.complete();
        },
        cancelOnError: true,
      );
      await done.future;
      stopped = _sub == null;
      lap(stopped ? 'stopped' : 'stream done');
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
          _voiceLoop = false;
        });
      }
    } finally {
      _sub?.cancel();
      _sub = null;
      _streamDone = null;
      _flush?.cancel();
      _flush = null;
      // A call cut off by Stop (or an error) did not finish.
      for (var i = 0; i < parts.length; i++) {
        final p = parts[i];
        if (p is ToolPart && p.state.running) parts[i] = p.failed('Stopped');
      }
      final keep =
          ChatEntry.textOf(parts).isNotEmpty || parts.any((p) => p is ToolPart);
      if (keep) {
        final saved = List<ChatPart>.of(parts);
        final reply = ChatEntry(
          id: 'local-${_localId++}',
          role: 'assistant',
          createdAt: DateTime.now().millisecondsSinceEpoch,
          parts: saved,
        );
        _persist('assistant message', () async {
          final chat = _chat;
          if (chat != null) {
            await widget.api.addEntry(chat, 'assistant', saved);
          }
        });
        if (mounted) _window.add(reply);
        // The saved answer takes the streamed one's place (and its key).
        _answerId = reply.id;
      }
      if (mounted) {
        setState(() {
          _sending = false;
          _partial = null;
        });
      }
      lap('done');
      _live?.parts.value = List.of(parts);
      // The run is over once its answer is written (or given up on).
      _persistTail.whenComplete(() {
        if (_live == live) _live = null;
        _liveRuns.removeWhere((_, r) => identical(r, live));
        if (!live._done.isCompleted) live._done.complete();
        if (_ownBridgeOpenUntilDone && !mounted) {
          final own = _ownBridge;
          if (own is WebViewToolBridge) own.close();
        }
      });
    }
    final answer = ChatEntry.textOf(parts);
    if (stopped || answer.isEmpty) return;
    if (_voiceLoop) {
      spoken = answer;
    } else if (widget.voiceMode && mounted) {
      (_outputInst ??= PluginSpeechOutput()).speak(answer);
    }
    if (spoken != null && mounted && _voiceLoop) await _speakThenListen(spoken);
  }

  /// Shows [parts] as the partial reply on the next tick of a ~30 fps
  /// clock: a fast stream redraws (and re-reads its Markdown) less often
  /// than it delivers pieces.
  void _showLater(List<ChatPart> parts) {
    if (_flush != null) return;
    // The first piece shows at once: the dots give way to text.
    final wait = _partial == null || _partial!.isEmpty
        ? Duration.zero
        : const Duration(milliseconds: 33);
    _flush = Timer(wait, () => _showNow(parts));
  }

  /// Shows [parts] as the partial reply now (a tool call starts or ends).
  void _showNow(List<ChatPart> parts) {
    _flush?.cancel();
    _flush = null;
    _live?.parts.value = List.of(parts);
    if (mounted && _partial != null) {
      setState(() => _partial = List.of(parts));
    }
  }

  /// An attached image, large.
  void _showImage(FilePart p) {
    final bytes = p.bytes;
    if (bytes == null) return;
    showDialog<void>(
      context: context,
      builder: (context) => Dialog(
        clipBehavior: Clip.antiAlias,
        child: InteractiveViewer(child: Image.memory(bytes)),
      ),
    );
  }

  /// Opens a link of a message: a resource in the app, anything else
  /// outside it.
  void _openLink(String url) {
    if (url.startsWith('atomic:') || url.startsWith('did:ad:')) {
      openFromList<void>(
        context,
        (_) => openResourceView(api: widget.api, drive: '', subject: url),
        subject: url,
      );
      return;
    }
    final uri = Uri.tryParse(url);
    if (uri == null || !uri.hasScheme) return;
    launchUrl(uri, mode: LaunchMode.externalApplication);
  }

  /// The chat exists now: in the shell this page is no longer the bar's
  /// "new chat", and New opens another.
  void _noLongerNew() {
    if (!mounted) return;
    final route = ModalRoute.of(context);
    if (route != null) ShellScope.maybeOf(context)?.setKind(route, null);
  }

  String get _headerTitle => widget.title.isEmpty
      ? (_chat == null
          ? (widget.voiceMode ? 'Voice chat' : 'New chat')
          : 'Untitled chat')
      : widget.title;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return ChatTextScope(
        child: SectionBack(
            section: HomeSection.chats,
            child: Scaffold(
              backgroundColor: c.bgBody,
              appBar: AppTopBar(
                compact: true,
                title: _headerTitle,
                titleWidget: ChatHeader(
                  title: _headerTitle,
                  subtitle: 'AI assistant',
                  icon: Icons.auto_awesome_outlined,
                ),
              ),
              body: ListAndField(
                  fullWidthField: true, list: _list(c), field: _composer(c)),
            )));
  }

  Widget _list(AppColors c) {
    if (_loadError != null) {
      return Center(
        child: ErrorText('$_loadError', color: c.alert),
      );
    }
    if (!_loaded) return const Center(child: CircularProgressIndicator());
    final shown = [
      ..._messages,
      if (_partial != null)
        ChatEntry(
            id: 'partial', role: 'assistant', createdAt: 0, parts: _partial!),
    ];
    if (shown.isEmpty) return _noAi ? _noAiState(c) : _picker(c);
    final ids = [for (final m in shown) m.id];
    final at = {for (var i = 0; i < ids.length; i++) ids[i]: i};
    if (_sending) _queueSettle();
    final list = LayoutBuilder(
      builder: (context, box) => NotificationListener<ScrollStartNotification>(
        onNotification: _onScrollStart,
        child: ListView.builder(
          key: _listKey,
          controller: _keeper.controller,
          reverse: true,
          physics: chatScrollPhysics,
          scrollCacheExtent: const ScrollCacheExtent.viewport(1.5),
          keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
          padding: readableHorizontalPadding(box.maxWidth,
                  gutter: ChatTextStyles.gutter)
              .copyWith(top: 8, bottom: 8 + _spacer),
          itemCount: shown.length + (_window.hasOlder ? 1 : 0),
          findChildIndexCallback: (key) => reversedIndexOf(key, ids, at),
          itemBuilder: (context, i) {
            if (i == shown.length) {
              // The top: older messages are being read.
              return const Padding(
                padding: EdgeInsets.all(12),
                child: Center(
                    child: SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2))),
              );
            }
            _keeper.built(i);
            final index = shown.length - 1 - i;
            final m = shown[index];
            final mine = m.role == 'user';
            final newDay = m.createdAt > 0 &&
                (index == 0 && !_window.hasOlder ||
                    index > 0 &&
                        shown[index - 1].createdAt > 0 &&
                        otherDay(shown[index - 1].createdAt, m.createdAt));
            final first = index == 0 || shown[index - 1].role != m.role;
            final last =
                index == shown.length - 1 || shown[index + 1].role != m.role;
            final bubble = Align(
              alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
              child: Container(
                margin: EdgeInsets.only(top: ChatTextStyles.gapAbove(first)),
                padding: ChatTextStyles.bubblePadding,
                constraints: BoxConstraints(
                  // An answer may hold code and tables: a little wider.
                  maxWidth: ChatTextStyles.bubbleMaxWidth(
                      box.maxWidth -
                          2 *
                              (ChatTextStyles.gutter +
                                  readableSideInset(box.maxWidth)),
                      answer: !mine),
                ),
                decoration: ChatTextStyles.bubbleDecoration(c,
                    mine: mine, joinAbove: !first, joinBelow: !last),
                child: _bubble(c, m, mine),
              ),
            );
            final keyed = m.id == _answerId
                ? KeyedSubtree(key: _answerKey, child: bubble)
                : m.id == _sentId
                    ? KeyedSubtree(key: _sentKey, child: bubble)
                    : bubble;
            return KeyedSubtree(
              key: ValueKey(m.id),
              child: newDay
                  ? Column(children: [
                      DaySeparator(dayLabel(m.createdAt),
                          color: c.textSecondary),
                      keyed,
                    ])
                  : keyed,
            );
          },
        ),
      ),
    );
    return Stack(children: [
      list,
      ScrollToBottomButton(keeper: _keeper),
    ]);
  }

  /// What a message shows: its text in Markdown, its tool calls as steps.
  Widget _bubble(AppColors c, ChatEntry m, bool mine) {
    final partial = m.id == 'partial';
    if (partial && m.parts.isEmpty) {
      return const SizedBox(
        width: 16,
        height: 16,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    }
    final titles = toolTitles(m.parts);
    final children = <Widget>[];
    final images = [
      for (final p in m.parts)
        if (p is FilePart && p.isImage) p,
    ];
    final others = [
      for (final p in m.parts)
        if (p is FilePart && !p.isImage)
          AttachmentChip(
            icon: Icons.description_outlined,
            label: p.filename ?? 'Attached file',
            onMine: mine,
          ),
      for (final r in m.context)
        AttachmentChip(
          icon: iconForClass(r.className),
          emoji: r.emoji,
          label: r.title.isEmpty ? 'Resource' : r.title,
          onMine: mine,
          onTap: () => _openLink(r.subject),
        ),
    ];
    if (images.isNotEmpty) {
      children.add(Wrap(
        spacing: 6,
        runSpacing: 6,
        children: [
          for (final p in images)
            ClickCursor(
              enabled: true,
              child: GestureDetector(
                onTap: () => _showImage(p),
                child: AttachmentThumb(p, size: images.length == 1 ? 160 : 96),
              ),
            ),
        ],
      ));
    }
    if (others.isNotEmpty) {
      if (children.isNotEmpty) children.add(const SizedBox(height: 6));
      children.add(Wrap(spacing: 6, runSpacing: 4, children: others));
    }
    for (var i = 0; i < m.parts.length; i++) {
      final p = m.parts[i];
      final last = i == m.parts.length - 1;
      final Widget? w = switch (p) {
        TextPart(:final text) when text.trim().isNotEmpty => MarkdownView(
            text,
            key: partial && last ? const Key('chat-partial') : null,
            streaming: partial && last,
            inline: mine,
            style: mine
                ? ChatTextStyles.of(context).bodyMine
                : ChatTextStyles.of(context).body,
            onLink: _openLink,
            linkColor: mine ? ChatTextStyles.onOwn : null,
          ),
        ToolPart() =>
          ToolStepRow(p, key: ValueKey(p.toolCallId), titles: titles),
        _ => null,
      };
      if (w == null) continue;
      if (children.isNotEmpty) {
        children.add(SizedBox(height: p is ToolPart ? 2 : 8));
      }
      children.add(w);
    }
    // Still thinking after a tool call: the dots say so.
    if (partial &&
        m.parts.last is ToolPart &&
        !(m.parts.last as ToolPart).state.running) {
      children.add(const Padding(
        padding: EdgeInsets.only(top: 6),
        child: SizedBox(
          width: 14,
          height: 14,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      ));
    }
    if (children.length == 1) return children.single;
    return Column(
      crossAxisAlignment:
          mine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: children,
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
        mouseCursor: WidgetStateMouseCursor.clickable,
        customBorder: const StadiumBorder(),
        onTap: () => _toggle(item),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 5),
          child: Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: ChatTextStyles.metaSize,
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
              style: TextStyle(
                  color: c.textSecondary, fontSize: ChatTextStyles.metaSize),
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

  /// What goes with the next message: photos and files, and the attached
  /// resources; each removable.
  Widget _chips(AppColors c) => Align(
        alignment: Alignment.centerLeft,
        child: Padding(
          padding: const EdgeInsets.only(bottom: 6),
          child: Wrap(
            spacing: 6,
            runSpacing: 4,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              for (final f in _files)
                if (f.isImage)
                  Stack(
                    key: ValueKey(f),
                    clipBehavior: Clip.none,
                    children: [
                      AttachmentThumb(f, size: 48),
                      Positioned(
                        top: -6,
                        right: -6,
                        child: _removeDot(
                            c, f.filename ?? 'image', () => _removeFile(f)),
                      ),
                    ],
                  )
                else
                  AttachmentChip(
                    key: ValueKey(f),
                    icon: Icons.description_outlined,
                    label: f.filename ?? 'File',
                    onRemove: () => _removeFile(f),
                  ),
              for (final a in _attached)
                Chip(
                  avatar: a.emoji == null
                      ? Icon(iconForClass(a.className), size: 16)
                      : Text(a.emoji!),
                  label: Text(a.title, overflow: TextOverflow.ellipsis),
                  visualDensity: VisualDensity.compact,
                  onDeleted: () => _toggle(a),
                  deleteButtonTooltipMessage: 'Remove ${a.title}',
                ),
            ],
          ),
        ),
      );

  Widget _removeDot(AppColors c, String name, VoidCallback onTap) => Material(
        color: c.bg2,
        shape: const CircleBorder(),
        child: InkResponse(
          mouseCursor: WidgetStateMouseCursor.clickable,
          onTap: onTap,
          radius: 14,
          child: Padding(
            padding: const EdgeInsets.all(3),
            child: Icon(Icons.close,
                size: 12, color: c.textPrimary, semanticLabel: 'Remove $name'),
          ),
        ),
      );

  void _removeFile(FilePart f) => setState(() => _files.remove(f));

  /// The attach button: photos, the camera, a file, or a resource.
  Future<void> _attach() async {
    final ai = _ai;
    if (ai == null) return;
    final picker = widget.attachmentPicker ?? defaultAttachmentPicker;
    final choice = await showAttachSheet(context,
        picker: picker, images: ai.acceptsImages);
    if (choice == null || !mounted) return;
    if (choice == AttachChoice.drive) {
      await _readPicker();
      if (!mounted) return;
      final r = await showDrivePicker(context, api: widget.api, recent: [
        for (final (_, r) in _recent ?? const <(String, RecentResource)>[]) r
      ]);
      if (r == null || !mounted) return;
      setState(() {
        _fromDrive.add(r.subject);
        if (!_attached.any((a) => a.subject == r.subject)) _attached.add(r);
      });
      return;
    }
    if (picker == null) return;
    List<PickedFile> files;
    try {
      files = switch (choice) {
        AttachChoice.photos => await picker.pickImages(),
        AttachChoice.camera => [
            if (await picker.takePhoto() case final f?) f,
          ],
        _ => await picker.pickFiles(),
      };
    } catch (e) {
      if (mounted) setState(() => _error = "Couldn't attach: $e");
      return;
    }
    String? problem;
    final parts = <FilePart>[];
    for (final f in files) {
      final p = attachmentProblem(f, images: ai.acceptsImages);
      if (p != null) {
        problem = p;
        continue;
      }
      parts.add(await attachmentPart(f));
    }
    if (!mounted) return;
    setState(() {
      _files.addAll(parts);
      _error = problem;
    });
  }

  /// Looked up, and there is no AI to write to (no account on the device).
  bool get _noAi => _aiLooked && _ai == null;

  static const _noAiTitle = 'AI chat needs an atomic.place account';

  /// What a new chat shows without an AI: why, instead of a context picker
  /// for a chat that cannot be had and a line under an empty page.
  Widget _noAiState(AppColors c) => Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.auto_awesome_outlined, size: 40, color: c.main),
              const SizedBox(height: 16),
              Text(
                _noAiTitle,
                key: const Key('no-ai-title'),
                textAlign: TextAlign.center,
                style: TextStyle(
                    color: c.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              Text(
                _error ??
                    'The AI runs on the account, and this device has none '
                        'linked. Your drives, documents and chat rooms work '
                        'without one.',
                textAlign: TextAlign.center,
                style: TextStyle(color: c.textSecondary, height: 1.4),
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
            style: TextStyle(
                color: c.textSecondary, fontSize: ChatTextStyles.statusSize),
            textAlign: TextAlign.center,
          ),
        );
    // While the AI is looked up, the field is there already, switched off:
    // the messages above stay where they are when the answer lands.
    if (_noAi) {
      // An empty chat says it in the middle (see [_noAiState]).
      if (_messages.isEmpty) return const SizedBox.shrink();
      return SafeArea(child: hint(_error ?? '$_noAiTitle.'));
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
                style: TextStyle(
                    color: c.textSecondary,
                    fontSize: ChatTextStyles.statusSize),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              FilledButton(
                onPressed: _enableAi,
                child: const Text('Turn on AI'),
              ),
              if (_error != null)
                ErrorText(_error!,
                    color: c.alert, fontSize: ChatTextStyles.metaSize),
            ],
          ),
        ),
      );
    }
    return ChatComposerFrame(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Text(
                _error!,
                style: TextStyle(
                    color: c.alert, fontSize: ChatTextStyles.metaSize),
              ),
            ),
          if (_files.isNotEmpty ||
              (_attached.isNotEmpty &&
                  (_messages.isNotEmpty ||
                      _attached.any((a) => _fromDrive.contains(a.subject)))))
            _chips(c),
          if (widget.voiceMode) _voiceBar(c),
          if (_listening) _Waveform(levels: _levels),
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              IconButton(
                key: const Key('chat-attach'),
                tooltip: 'Attach',
                onPressed: ai == null || _transcribing ? null : _attach,
                icon: const Icon(Icons.add_circle_outline),
              ),
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
                  style: ChatTextStyles.of(context).composer,
                  decoration: chatFieldDecoration(context),
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
              if (_sending)
                ChatSendButton(
                  key: const Key('chat-stop'),
                  tooltip: 'Stop',
                  onPressed: _stopAnswer,
                  icon: Icons.stop,
                )
              else
                ChatSendButton(
                  key: _listening ? const Key('chat-stop-and-send') : null,
                  // While dictating, this is stop and send in one tap.
                  tooltip: _listening ? 'Stop and send' : 'Send',
                  onPressed: _transcribing || _finalising || ai == null
                      ? null
                      : _listening
                          ? (_voiceLoop ? null : _stopAndSend)
                          : !(_hadText || _files.isNotEmpty)
                              ? null
                              : _send,
                ),
            ],
          ),
          if (_voiceNote != null)
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text(
                _voiceNote!,
                key: const Key('voice-note'),
                style: TextStyle(
                    color: c.textSecondary, fontSize: ChatTextStyles.metaSize),
              ),
            ),
          if (_noSpeechHint && !_listening)
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text(
                "Didn't hear anything. Check the language (long-press the "
                'mic) and try again.',
                key: const Key('voice-hint'),
                style: TextStyle(
                    color: c.textSecondary, fontSize: ChatTextStyles.metaSize),
              ),
            ),
        ],
      ),
    );
  }

  /// Voice mode: what the loop is doing, and Stop (or Talk to resume).
  Widget _voiceBar(AppColors c) {
    final status = _speaking
        ? 'Speaking…'
        : _sending
            ? 'Thinking…'
            : _transcribing
                ? 'Transcribing…'
                : _listening
                    ? 'Listening…'
                    : 'Voice paused';
    final running = _voiceLoop || _speaking;
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        children: [
          Expanded(
            child: Text(
              status,
              key: const Key('voice-status'),
              style: TextStyle(
                  color: c.textSecondary, fontSize: ChatTextStyles.statusSize),
            ),
          ),
          running
              ? FilledButton.tonalIcon(
                  key: const Key('voice-stop'),
                  onPressed: _stopVoice,
                  icon: const Icon(Icons.stop),
                  label: const Text('Stop'),
                )
              : FilledButton.icon(
                  key: const Key('voice-talk'),
                  onPressed: _ai == null || _sending ? null : _startVoice,
                  icon: const Icon(Icons.mic),
                  label: const Text('Talk'),
                ),
        ],
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
