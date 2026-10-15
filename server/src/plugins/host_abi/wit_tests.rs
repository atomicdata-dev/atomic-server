//! The host ABI's interface definition, `atomic-host/wit/host.wit`, must parse
//! and expose what the host and the guests are written against.

use wit_parser::Resolve;

fn resolve() -> (Resolve, wit_parser::PackageId) {
    let mut resolve = Resolve::new();
    let (package, _) = resolve
        .push_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../atomic-host/wit"))
        .expect("atomic-host/wit parses");
    (resolve, package)
}

#[test]
fn the_wit_parses_with_the_interfaces_and_worlds_the_host_implements() {
    let (resolve, package) = resolve();
    let package = &resolve.packages[package];
    assert_eq!(package.name.to_string(), "atomic:host@0.1.0");

    for interface in ["types", "store", "events", "net", "calls", "app"] {
        assert!(
            package.interfaces.contains_key(interface),
            "missing interface {interface}"
        );
    }
    for world in ["sandboxed-app", "server-module"] {
        assert!(package.worlds.contains_key(world), "missing world {world}");
    }
}
