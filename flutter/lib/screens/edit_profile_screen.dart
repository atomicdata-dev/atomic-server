import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:atomic_chat/atomic_chat.dart' show AppTopBar, ProfileAvatar;
import 'package:flutter/material.dart';

import '../theme.dart';

/// Edits the person's own profile: their name and description, saved as a
/// commit by their agent (synced like any other edit). The picture is shown,
/// not changed here: the app has no photo picker yet.
///
/// Pops with true when saved.
class EditProfileScreen extends StatefulWidget {
  final shared.AtomicIdentity agent;
  final Future<void> Function(
      {required String name, required String description}) save;

  const EditProfileScreen({super.key, required this.agent, required this.save});

  @override
  State<EditProfileScreen> createState() => _EditProfileScreenState();
}

class _EditProfileScreenState extends State<EditProfileScreen> {
  late final _name = TextEditingController(text: widget.agent.name ?? '');
  late final _description =
      TextEditingController(text: widget.agent.description ?? '');
  bool _saving = false;
  String? _error;

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
      await widget.save(name: name, description: _description.text.trim());
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
              name: _name.text,
              imageUrl: widget.agent.imageUrl,
              imageBytes: widget.agent.imageBytes,
              emoji: widget.agent.emoji,
              radius: 44,
            ),
          ),
          const SizedBox(height: 24),
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
            Text(_error!, style: TextStyle(color: c.alert)),
          ],
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
