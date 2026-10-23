/// A working Atomic Data `Store` for Flutter apps, backed by the Rust
/// `atomic_lib` node (local database, signed commits, search, server sync).
///
/// See the README for the five-line start.
library;

export 'src/atomic_flutter.dart' show AtomicFlutter, AtomicNode;
export 'src/bridge_store_backend.dart'
    show
        BridgeStoreBackend,
        BridgeResourceApi,
        propsFromBridge,
        propsToBridge,
        storeExceptionFromBridge,
        valueFromBridge,
        valueToBridge;
