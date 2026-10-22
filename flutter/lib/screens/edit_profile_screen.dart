import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:atomic_chat/atomic_chat.dart' show AppTopBar, ProfileAvatar;
import 'package:flutter/material.dart';

import '../theme.dart';

/// Edits the person's own profile: picture, name and description, saved as a
/// commit by their agent (synced like any other edit). The picture can be
/// changed or removed when the host can pick one ([pickPicture]); without it
/// the picture is only shown.
///
/// Pops with true when saved, with false (or nothing) on Cancel.
class EditProfileScreen extends StatefulWidget {
  final shared.AtomicIdentity agent;
  final Future<void> Function(
      {required String name,
      required String description,
      shared.ProfilePicture? picture,
      bool? removePicture}) save;

  /// Lets the person pick a picture; null when they cancel. Null here: the
  /// picture cannot be changed.
  final Future<shared.ProfilePicture?> Function()? pickPicture;

  const EditProfileScreen(
      {super.key, required this.agent, required this.save, this.pickPicture});

  @override
  State<EditProfileScreen> createState() => _EditProfileScreenState();
}

class _EditProfileScreenState extends State<EditProfileScreen> {
  late final _name = TextEditingController(text: widget.agent.name ?? '');
  late final _description =
      TextEditingController(text: widget.agent.description ?? '');
  bool _saving = false;
  String? _error;

  /// The picture picked now (not saved yet), or the existing one taken away.
  shared.ProfilePicture? _picked;
  bool _removed = false;

  bool get _hasPicture =>
      _picked != null ||
      (!_removed &&
          (widget.agent.imageBytes != null || widget.agent.imageUrl != null));

  Future<void> _pick() async {
    final pick = widget.pickPicture;
    if (pick == null || _saving) return;
    try {
      final picture = await pick();
      if (picture == null || !mounted) return;
      setState(() {
        _picked = picture;
        _removed = false;
        _error = null;
      });
    } catch (e) {
      if (mounted) {
        setState(() => _error = '$e'.replaceFirst('Bad state: ', ''));
      }
    }
  }

  void _remove() => setState(() {
        _picked = null;
        _removed = true;
      });

  @override
  void initState() {
    super.initState();
    _name.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    _name.dispose();
    _description.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final name = _name.text.trim();
    if (name.isEmpty || _saving) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      await widget.save(
          name: name,
          description: _description.text.trim(),
          picture: _picked,
          removePicture: _removed ? true : null);
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _saving = false;
          _error = '$e';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final canSave = _name.text.trim().isNotEmpty && !_saving;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(title: 'Profile', actions: [
        TextButton(
          onPressed: canSave ? _save : null,
          child: _saving
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2))
              : const Text('Save'),
        ),
      ]),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Center(
            child: ProfileAvatar(
              key: ValueKey(_picked ?? _removed),
              name: _name.text,
              imageUrl:
                  _picked != null || _removed ? null : widget.agent.imageUrl,
              imageBytes: _picked != null
                  ? _picked!.bytes
                  : (_removed ? null : widget.agent.imageBytes),
              emoji: widget.agent.emoji,
              radius: 44,
            ),
          ),
          if (widget.pickPicture != null) ...[
            const SizedBox(height: 8),
            Wrap(
              alignment: WrapAlignment.center,
              spacing: 8,
              children: [
                TextButton.icon(
                  key: const Key('profile-change-photo'),
                  style: TextButton.styleFrom(minimumSize: const Size(48, 48)),
                  onPressed: _saving ? null : _pick,
                  icon: const Icon(Icons.photo_outlined, size: 20),
                  label: Text(_hasPicture ? 'Change photo' : 'Add photo'),
                ),
                if (_hasPicture)
                  TextButton.icon(
                    key: const Key('profile-remove-photo'),
                    style:
                        TextButton.styleFrom(minimumSize: const Size(48, 48)),
                    onPressed: _saving ? null : _remove,
                    icon: const Icon(Icons.delete_outline, size: 20),
                    label: const Text('Remove photo'),
                  ),
              ],
            ),
          ],
          const SizedBox(height: 16),
          TextField(
            key: const Key('profile-name'),
            controller: _name,
            textCapitalization: TextCapitalization.words,
            textInputAction: TextInputAction.next,
            decoration: const InputDecoration(
                labelText: 'Name', border: OutlineInputBorder()),
          ),
          const SizedBox(height: 16),
          TextField(
            key: const Key('profile-description'),
            controller: _description,
            minLines: 3,
            maxLines: 6,
            textCapitalization: TextCapitalization.sentences,
            decoration: const InputDecoration(
                labelText: 'Description',
                alignLabelWithHint: true,
                border: OutlineInputBorder()),
          ),
          if (_error != null) ...[
            const SizedBox(height: 12),
            shared.ErrorText(_error!, color: c.alert),
          ],
          const SizedBox(height: 16),
          OutlinedButton(
            key: const Key('profile-cancel'),
            style: OutlinedButton.styleFrom(minimumSize: const Size(0, 48)),
            onPressed: _saving ? null : () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          const SizedBox(height: 16),
          Text(
            'Others see this name and description wherever you show up: '
            'in chats, comments and the history of what you edit.',
            style: TextStyle(color: c.textSecondary, fontSize: 13),
          ),
        ],
      ),
    );
  }
}
