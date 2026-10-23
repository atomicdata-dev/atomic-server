import 'dart:io' show Platform;

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart'
    show ExternalLibrary;

import '../bridge/frb_generated.dart';

Future<void> initRustBridge() => RustLib.init(externalLibrary: nativeLibrary());

/// The native library, where the bridge's default loader would not find it.
///
/// On iOS and macOS the Rust library is linked into this plugin's pod, so
/// it ships as `atomic_store_flutter.framework`; the generated loader looks
/// for `<crate>.framework` (`atomic_flutter_rust`). Elsewhere the library
/// carries the crate's name and the default loader finds it (null).
ExternalLibrary? nativeLibrary() => Platform.isIOS || Platform.isMacOS
    ? ExternalLibrary.open(
        'atomic_store_flutter.framework/atomic_store_flutter')
    : null;
