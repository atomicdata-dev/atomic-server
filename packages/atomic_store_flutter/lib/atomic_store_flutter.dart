/// A working Atomic Data `Store` for Flutter apps, backed by the Rust
/// `atomic_lib` node (local database, signed commits, search, server sync).
///
/// See the README for the five-line start.
library;

export 'src/atomic_flutter.dart' show AtomicFlutter, AtomicNode;
export 'src/drives.dart' show Drives, DriveInfo, BridgeDrives, drivesFromBridge;
export 'src/identity.dart' show Identity, Profile, SignIn, BridgeIdentity;
export 'src/pairing.dart' show PairingCode;
export 'src/peers.dart'
    show
        Peers,
        BridgePeers,
        KnownPeer,
        LivePeer,
        PeerEvent,
        PeerSearchStatus,
        PeerSyncResult,
        PeersSyncResult,
        knownPeersFromBridge,
        peerSyncResultFromBridge;
export 'src/server_sync.dart'
    show
        ServerSync,
        BridgeServerSync,
        HomeServerDiscovery,
        ResumeStatus,
        SyncStatus;
export 'src/sharing.dart' show Sharing, ShareRole, Access, InviteSigner;
export 'src/init_native.dart' if (dart.library.js_interop) 'src/init_web.dart'
    show nativeLibrary;
export 'src/bridge_store_backend.dart'
    show
        BridgeStoreBackend,
        BridgeResourceApi,
        propsFromBridge,
        propsToBridge,
        storeExceptionFromBridge,
        valueFromBridge,
        valueToBridge;
