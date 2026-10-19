import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_api.dart';
import 'models.dart';

/// SharedPreferences key: the drive the last new resource went into.
const newResourceDriveKey = 'new_resource_drive';

/// The class of a document, as the web app's "Document" button makes it.
const documentClass = 'https://atomicdata.dev/classes/DocumentV2';

/// The drive a new resource went into last, if any.
Future<String?> lastNewResourceDrive() async {
  try {
    return (await SharedPreferences.getInstance())
        .getString(newResourceDriveKey);
  } catch (_) {
    return null;
  }
}

Future<void> _rememberDrive(String drive) async {
  try {
    await (await SharedPreferences.getInstance())
        .setString(newResourceDriveKey, drive);
  } catch (_) {}
}

/// The person's drives, the one with the most recently opened resource first
/// (drives nothing was opened in keep their order, last).
Future<List<DriveInfo>> drivesByRecent(AssistantApi api) async {
  final drives = await api.drives();
  final latest = await Future.wait([
    for (final d in drives)
      api.recentResources(d.subject).then(
            (list) =>
                list.fold<int>(0, (m, r) => r.openedAt > m ? r.openedAt : m),
            onError: (Object _) => 0,
          ),
  ]);
  final order = List.generate(drives.length, (i) => i)
    ..sort((a, b) {
      final byTime = latest[b].compareTo(latest[a]);
      return byTime != 0 ? byTime : a.compareTo(b);
    });
  return [for (final i in order) drives[i]];
}

/// A drive's name as a label.
String driveLabel(DriveInfo d) {
  final name = d.name.isEmpty ? 'Untitled drive' : d.name;
  return d.emoji == null ? name : '${d.emoji} $name';
}

/// What [NewDocumentSheet] made.
typedef CreatedResource = ({String drive, String subject, String name});

/// Opens [NewDocumentSheet]; answers what was created, null when nothing was.
Future<CreatedResource?> showNewDocumentSheet(
  BuildContext context, {
  required AssistantApi api,
  String fallbackDrive = '',
}) =>
    showModalBottomSheet<CreatedResource>(
      context: context,
      isScrollControlled: true,
      builder: (_) => NewDocumentSheet(api: api, fallbackDrive: fallbackDrive),
    );

/// A new document, natively: a name (empty is "Untitled"), the drive it goes
/// in (the last one used preselected, most recently used drives first) and
/// Create. Pops with the [CreatedResource]; errors stay in the sheet.
class NewDocumentSheet extends StatefulWidget {
  final AssistantApi api;

  /// The drive used when the drives cannot be listed.
  final String fallbackDrive;

  /// The class of what is made.
  final String classUrl;

  const NewDocumentSheet({
    super.key,
    required this.api,
    this.fallbackDrive = '',
    this.classUrl = documentClass,
  });

  @override
  State<NewDocumentSheet> createState() => _NewDocumentSheetState();
}

class _NewDocumentSheetState extends State<NewDocumentSheet> {
  final _name = TextEditingController();
  List<DriveInfo>? _drives;
  String? _drive;
  bool _creating = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    List<DriveInfo> drives;
    try {
      drives = await drivesByRecent(widget.api);
    } catch (_) {
      drives = const [];
    }
    if (drives.isEmpty && widget.fallbackDrive.isNotEmpty) {
      drives = [(subject: widget.fallbackDrive, name: '', emoji: null)];
    }
    final last = await lastNewResourceDrive();
    if (!mounted) return;
    setState(() {
      _drives = drives;
      _drive = drives
              .where(
                  (d) => last != null && driveKey(d.subject) == driveKey(last))
              .map((d) => d.subject)
              .firstOrNull ??
          drives.firstOrNull?.subject;
    });
  }

  Future<void> _create() async {
    final drive = _drive;
    if (drive == null || _creating) return;
    final name = _name.text.trim();
    setState(() {
      _creating = true;
      _error = null;
    });
    try {
      final subject =
          await widget.api.createResource(drive, widget.classUrl, name);
      await _rememberDrive(drive);
      if (mounted) {
        Navigator.of(context).pop<CreatedResource>((
          drive: drive,
          subject: subject,
          name: name.isEmpty ? 'Untitled' : name,
        ));
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _creating = false;
          _error = '$e';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final drives = _drives;
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text('New document',
                  style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 12),
              TextField(
                key: const Key('new-document-name'),
                controller: _name,
                autofocus: true,
                textInputAction: TextInputAction.done,
                onSubmitted: (_) => _create(),
                decoration: InputDecoration(
                  hintText: 'Untitled',
                  filled: true,
                  fillColor: c.bg1,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(9),
                    borderSide: BorderSide.none,
                  ),
                ),
              ),
              const SizedBox(height: 12),
              Text('Drive',
                  style: TextStyle(color: c.textSecondary, fontSize: 12)),
              const SizedBox(height: 4),
              if (drives == null)
                const Padding(
                  padding: EdgeInsets.all(8),
                  child: Center(
                      child: SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))),
                )
              else if (drives.isEmpty)
                Text('No drive to create it in.',
                    style: TextStyle(color: c.alert, fontSize: 13))
              else
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children: [
                      for (final d in drives)
                        Padding(
                          padding: const EdgeInsets.only(right: 6),
                          child: ChoiceChip(
                            key: ValueKey('drive-${d.subject}'),
                            label: Text(driveLabel(d)),
                            selected: d.subject == _drive,
                            onSelected: _creating
                                ? null
                                : (_) => setState(() => _drive = d.subject),
                          ),
                        ),
                    ],
                  ),
                ),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text(_error!,
                      key: const Key('new-document-error'),
                      style: TextStyle(color: c.alert, fontSize: 13)),
                ),
              const SizedBox(height: 12),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton(
                  onPressed: _drive == null || _creating ? null : _create,
                  child: _creating
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Create'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
