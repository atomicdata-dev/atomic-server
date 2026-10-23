import 'package:atomic_store/atomic_store.dart';

/// What an agent may do with a resource (and, through `parent`, everything
/// under it). Mirrors `ShareRole` of the web app.
enum ShareRole {
  /// May see it.
  read,

  /// May see and change it.
  write,
}

/// One agent's direct right on a resource.
class Access {
  const Access(this.agent, this.role);

  /// The agent's subject, or [Sharing.publicAgent] for everyone.
  final String agent;
  final ShareRole role;

  bool get isPublic => agent == Props.publicAgent;

  @override
  bool operator ==(Object other) =>
      other is Access && other.agent == agent && other.role == role;

  @override
  int get hashCode => Object.hash(agent, role);

  @override
  String toString() => 'Access($agent, ${role.name})';
}

/// Signs an invite for `target` ([write] or read only) as the node's agent.
typedef InviteSigner = String Function(
    String target, bool write, int? expiresAtMs, int? maxUsages);

/// Who may read or write a resource, and how to invite someone.
///
/// **Rights** are the `read` and `write` properties of a resource (lists of
/// agent subjects, inherited down `parent`): sharing is an ordinary signed
/// write of those two lists, exactly what the web app's Share dialog does.
/// Writers are also listed as readers, so no server has to infer read access
/// from write access. The signed-in agent must itself be allowed to write
/// the resource.
///
/// **Invites** are stateless: a token the inviting agent signs for a target
/// resource (see `generateInviteToken` in `@tomic/lib`). Nothing is stored;
/// whoever opens `<server>/app/invite?token=<token>` and accepts is granted
/// the right by the server that hosts the target, which checks the token's
/// signature and that the inviter may share it. Accepting an invite happens
/// in that server's web app (or its `/invites` endpoint); this package only
/// creates them. An invite only works for a resource on a server, so connect
/// the node (`node.sync`) first.
///
/// ```dart
/// await node.sharing.grant(folder, friendAgent, ShareRole.write);
/// await node.sharing.setPublic(folder, ShareRole.read);   // anyone may read
/// final link = node.sharing.inviteLink('https://my.server', folder,
///     role: ShareRole.read, maxUsages: 5);
/// ```
class Sharing {
  Sharing(this._store, this._sign);

  final Store _store;
  final InviteSigner _sign;

  /// The agent that stands for everyone, signed in or not.
  static const publicAgent = Props.publicAgent;

  /// The rights set directly on [subject], one entry per agent (writers
  /// as [ShareRole.write]). Rights inherited from its parents are not listed.
  Future<List<Access>> rights(String subject) async {
    final resource = await _store.getResource(subject, fresh: true);
    final writers = resource.getLinks(Props.write);
    final readers = resource.getLinks(Props.read);
    return [
      for (final agent in {...writers, ...readers})
        Access(
            agent, writers.contains(agent) ? ShareRole.write : ShareRole.read)
    ];
  }

  /// Gives [agent] the [role] on [subject] (replacing its earlier role there).
  Future<void> grant(String subject, String agent, ShareRole role) =>
      _edit(subject, agent, role);

  /// Takes the direct right of [agent] on [subject] away. A right inherited
  /// from a parent stays.
  Future<void> revoke(String subject, String agent) =>
      _edit(subject, agent, null);

  /// What everyone may do with [subject] by its own rights, `null` when it
  /// is not public by them.
  Future<ShareRole?> publicAccess(String subject) async {
    for (final a in await rights(subject)) {
      if (a.isPublic) return a.role;
    }
    return null;
  }

  /// Lets everyone read ([ShareRole.read]) or write ([ShareRole.write])
  /// [subject], or with `null` stops doing so. Anyone with the link can then
  /// open it, without an account or invite.
  Future<void> setPublic(String subject, ShareRole? level) =>
      _edit(subject, publicAgent, level);

  Future<void> _edit(String subject, String agent, ShareRole? role) async {
    final resource = await _store.getResource(subject, fresh: true);
    final writers =
        resource.getLinks(Props.write).where((a) => a != agent).toList();
    final readers =
        resource.getLinks(Props.read).where((a) => a != agent).toList();
    if (role == ShareRole.write) writers.add(agent);
    if (role != null) readers.add(agent);
    void put(String property, List<String> agents) => agents.isEmpty
        ? resource.remove(property)
        : resource.set(
            property, ArrayValue([for (final a in agents) LinkValue(a)]));
    put(Props.write, writers);
    put(Props.read, readers);
    await resource.save();
  }

  /// A signed invite token for [target] (a drive or any resource the agent
  /// can share). [expiresAt] defaults to 30 days from now, [maxUsages]
  /// (at least 1) to unlimited.
  String inviteToken(String target,
      {ShareRole role = ShareRole.read, DateTime? expiresAt, int? maxUsages}) {
    if (maxUsages != null && maxUsages < 1) {
      throw const StoreException(StoreErrorKind.invalid,
          'The usage limit of an invite must be a whole number of at least 1.');
    }
    return _sign(target, role == ShareRole.write,
        expiresAt?.millisecondsSinceEpoch, maxUsages);
  }

  /// The link to give a person: `<serverOrigin>/app/invite?token=<token>`.
  String inviteLink(String serverOrigin, String target,
          {ShareRole role = ShareRole.read,
          DateTime? expiresAt,
          int? maxUsages}) =>
      inviteUrl(
          serverOrigin,
          inviteToken(target,
              role: role, expiresAt: expiresAt, maxUsages: maxUsages));

  /// The invite link for an existing [token].
  static String inviteUrl(String serverOrigin, String token) =>
      '${serverOrigin.trim().replaceAll(RegExp(r'/+$'), '')}/app/invite?token=${Uri.encodeComponent(token)}';
}
