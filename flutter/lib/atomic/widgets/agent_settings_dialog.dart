import 'package:flutter/material.dart';
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import '../settings_backend.dart';

/// Compatibility entry point; the actual dialog lives in atomic_flutter.
class AgentSettingsDialog extends StatelessWidget {
  const AgentSettingsDialog({super.key});

  static Future<bool> show(BuildContext context) =>
      shared.AgentSettingsDialog.show(
        context,
        backend: AppSettingsBackend(),
      );

  @override
  Widget build(BuildContext context) =>
      shared.AgentSettingsDialog(backend: AppSettingsBackend());
}
