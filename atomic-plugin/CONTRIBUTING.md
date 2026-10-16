# Contributing to Atomic Plugin

The bindings are generated at build time from `../atomic-host/wit` (world
`server-module`) by `wit_bindgen::generate!` in `src/lib.rs`; nothing is checked
in. `pub_export_macro` and `default_bindings_module` are what let a plugin crate
call `export_plugin!`: it expands to the export macro of `atomic_plugin::bindings`.

When the WIT changes, rebuild the plugins that use the crate (`plugin-examples/`)
and, for the Rust fixtures, run `scripts/build-host-abi-fixtures.sh`.

The crate depends on a path outside itself (`../atomic-host/wit`), so it cannot be
published as it is: copy the WIT in first.
