/// What a pairing QR code or pasted text says: which device to reach.
///
/// A pairing code is **routing only**. It names a node, and optionally where
/// else to find it. It grants nothing: the node dialed still proves it holds
/// the same agent key before any resource crosses.
class PairingCode {
  const PairingCode(this.nodeId, {this.name = '', this.serverUrl, this.drives});

  /// The Iroh node id: 64 lowercase hex characters.
  final String nodeId;

  /// The device's own name, when the code carries it.
  final String name;

  /// An http(s) server the code advertises: a routing hint, never identity.
  final String? serverUrl;

  /// The drives to sync. `null` means all of the agent's drives.
  final List<String>? drives;

  static const _node = 'atomic:node:';
  static const _didNode = 'did:ad:node:';
  static const _legacyPair = 'atomic://pair?';
  static final _hex = RegExp(r'^[a-f0-9]{64}$', caseSensitive: false);

  /// The text for a QR code: `atomic:node:<id>`, with the device [name]
  /// appended (`:<name>`, URI-encoded) when it has one.
  static String format(String nodeId, [String name = '']) => name.isEmpty
      ? '$_node$nodeId'
      : '$_node$nodeId:${Uri.encodeComponent(name)}';

  /// Reads a scanned or pasted code; `null` when it is not one. Understood:
  ///
  /// - `atomic:node:<id>[?v=1&url=<server>&drives=<a>&drives=<b>]` and the
  ///   older `did:ad:node:<id>` spelling (also `…:<id>:<name>`);
  /// - `atomic://pair?v=1&node=did:ad:node:<id>&url=…&drives=…`, which the web
  ///   and desktop apps show;
  /// - `iroh:<id>` and the bare 64 hex characters.
  ///
  /// A code of an unknown version, or one that carries a `secret`, is
  /// refused rather than read as far as it parses: dialing the wrong node on
  /// a half-understood code is worse than saying no.
  static PairingCode? parse(String input) {
    final text = input.trim();
    if (text.startsWith(_legacyPair) ||
        text.startsWith('atomic:pair?') ||
        text == 'atomic://pair') {
      final q = text.indexOf('?');
      return _fromEnvelope(q == -1 ? '' : text.substring(q + 1));
    }

    final bare = text.split(RegExp(r'[?#]')).first;
    for (final prefix in [_node, _didNode]) {
      if (!bare.startsWith(prefix)) continue;
      final rest = bare.substring(prefix.length);
      if (_hex.hasMatch(rest)) {
        final q = text.indexOf('?');
        return _fromQuery(
            rest.toLowerCase(), q == -1 ? '' : text.substring(q + 1));
      }
      // `<id>:<name>`
      if (rest.length > 64 &&
          rest[64] == ':' &&
          _hex.hasMatch(rest.substring(0, 64))) {
        return PairingCode(rest.substring(0, 64).toLowerCase(),
            name: Uri.decodeComponent(rest.substring(65)));
      }
      return null;
    }
    var id = text;
    if (id.startsWith('iroh:')) id = id.substring(5);
    return _hex.hasMatch(id) ? PairingCode(id.toLowerCase()) : null;
  }

  static PairingCode? _fromEnvelope(String query) {
    final Map<String, List<String>> params;
    try {
      params = Uri.parse('atomic:x?$query').queryParametersAll;
    } on FormatException {
      return null;
    }
    final version = params['v']?.last;
    if (version != null && version != '1') return null;
    final node = params['node']?.last;
    if (node == null) return null;
    final id = node.startsWith(_node)
        ? node.substring(_node.length)
        : node.startsWith(_didNode)
            ? node.substring(_didNode.length)
            : null;
    if (id == null || !_hex.hasMatch(id)) return null;
    return _build(id.toLowerCase(), params);
  }

  static PairingCode? _fromQuery(String id, String query) {
    if (query.isEmpty) return PairingCode(id);
    final Map<String, List<String>> params;
    try {
      params = Uri.parse('atomic:x?$query').queryParametersAll;
    } on FormatException {
      return null;
    }
    final version = params['v']?.last;
    if (version != null && version != '1') return null;
    if (params.containsKey('secret')) return null;
    return _build(id, params);
  }

  static PairingCode _build(String id, Map<String, List<String>> params) {
    final drives = params['drives']?.where((d) => d != '*').toList();
    return PairingCode(id,
        serverUrl: params['url']?.last,
        drives: drives == null || drives.isEmpty ? null : drives);
  }

  @override
  bool operator ==(Object other) =>
      other is PairingCode &&
      other.nodeId == nodeId &&
      other.name == name &&
      other.serverUrl == serverUrl &&
      _sameList(other.drives, drives);

  @override
  int get hashCode => Object.hash(nodeId, name, serverUrl, drives?.join(','));

  @override
  String toString() => 'PairingCode($nodeId${name.isEmpty ? '' : ', $name'})';

  static bool _sameList(List<String>? a, List<String>? b) =>
      a == null || b == null
          ? a == b
          : a.length == b.length &&
              Iterable<int>.generate(a.length).every((i) => a[i] == b[i]);
}
