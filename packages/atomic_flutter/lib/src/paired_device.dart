/// A paired device (an Iroh peer) as the Devices list shows it, read from one
/// row of [AtomicSettingsBackend.getKnownPeers].
///
/// The host sends strings. Fields an older host does not send are absent, and
/// the device then reads as it always did: "Paired", no owner. See
/// `planning/flutter-pairing-other-agents.md` for the fields the host is meant
/// to add (`agent`, `agent_name`, `relation`).
library;

/// Whose device it is, as far as this device knows.
enum PeerRelation {
  /// Signed in as this device's own agent: one of your devices.
  sameAgent,

  /// An always-on device the owner chose to hold their data.
  replica,

  /// Someone else's device: it gets only what its agent may read.
  contact,

  /// Not known yet (an older host, or never connected since pairing).
  unknown,
}

class PairedDevice {
  const PairedDevice({
    required this.nodeId,
    this.name = '',
    this.agent,
    this.agentName,
    this.relation = PeerRelation.unknown,
    this.lastSynced,
    this.lastSent,
    this.lastReceived,
    this.relayUrl,
    this.drives = 0,
  });

  final String nodeId;

  /// What the device calls itself (its HELLO), e.g. "Polle's iPhone".
  final String name;

  /// The agent the device proved it acts for, if the host recorded it.
  final String? agent;

  /// That agent's name, if the host could read its profile.
  final String? agentName;

  final PeerRelation relation;

  /// Unix millis of the last completed sync.
  final int? lastSynced;
  final int? lastSent;
  final int? lastReceived;
  final String? relayUrl;

  /// How many workspaces are synced with this device.
  final int drives;

  /// Reads a `getKnownPeers` row. [ownAgent] decides the relation when the
  /// host recorded the peer's agent but not the relation itself.
  factory PairedDevice.fromRow(Map<String, String> row, {String? ownAgent}) {
    String? text(String key) {
      final value = row[key]?.trim();
      return value == null || value.isEmpty ? null : value;
    }

    int? number(String key) => int.tryParse(row[key] ?? '');

    final agent = text('agent');
    var relation = switch (text('relation')) {
      'same_agent' || 'sameAgent' => PeerRelation.sameAgent,
      'replica' => PeerRelation.replica,
      'contact' || 'other_agent' => PeerRelation.contact,
      _ => PeerRelation.unknown,
    };
    if (relation == PeerRelation.unknown && agent != null && ownAgent != null) {
      relation =
          agent == ownAgent ? PeerRelation.sameAgent : PeerRelation.contact;
    }

    return PairedDevice(
      nodeId: row['node_id'] ?? '',
      name: (row['name'] ?? '').trim(),
      agent: agent,
      agentName: text('agent_name'),
      relation: relation,
      lastSynced: number('last_synced'),
      lastSent: number('last_sent'),
      lastReceived: number('last_received'),
      relayUrl: text('relay_url'),
      drives: number('drives') ?? 0,
    );
  }

  bool get isOtherPerson => relation == PeerRelation.contact;

  /// The device's own name, else a short id.
  String get deviceLabel => name.isNotEmpty
      ? name
      : '${nodeId.substring(0, nodeId.length.clamp(0, 12))}…';

  /// Who and which device: "Polle · iPhone" for someone else's, the device
  /// name alone for your own.
  String get label {
    final owner = agentName;
    if (isOtherPerson && owner != null && owner.isNotEmpty) {
      return name.isEmpty || name == owner ? owner : '$owner · $name';
    }
    return deviceLabel;
  }

  /// The chip: whose it is, when that is known.
  String? get relationLabel => switch (relation) {
        PeerRelation.sameAgent => 'Your device',
        PeerRelation.contact => 'Shared with you',
        PeerRelation.replica => 'Holds your data',
        PeerRelation.unknown => null,
      };

  /// What the last sync moved, or null before the first one.
  String? get lastSyncCounts {
    final sent = lastSent;
    final received = lastReceived;
    if (sent == null && received == null) return null;
    return [
      if (received != null) 'received $received',
      if (sent != null) 'sent $sent',
    ].join(', ');
  }

  /// Initials for the avatar: "PS" for "Polle Smit".
  String get initials {
    final source = (agentName?.isNotEmpty ?? false) ? agentName! : name;
    final words =
        source.split(RegExp(r'\s+')).where((w) => w.isNotEmpty).toList();
    if (words.isEmpty) return '?';
    String firstOf(String w) => String.fromCharCode(w.runes.first);
    return words.take(2).map(firstOf).join().toUpperCase();
  }
}
