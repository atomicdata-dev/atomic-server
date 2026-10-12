import 'package:flutter/material.dart';
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import '../settings_backend.dart';

class ServerSettingsSection extends StatelessWidget {
  const ServerSettingsSection({super.key, this.onServerChanged});
  final VoidCallback? onServerChanged;

  @override
  Widget build(BuildContext context) => shared.ServerSettingsSection(
        backend: CanvasSettingsBackend(),
        onServerChanged: onServerChanged,
      );
}
