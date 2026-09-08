# Test Plugin

This plugin is used in the end to end tests.

## Building

To build the plugin run:

```bash
cargo build --release -p test-plugin --target wasm32-wasip2
(cd ui && pnpm install && pnpm build)
cargo run --bin package -- --wasm ../../target/wasm32-wasip2/release/test_plugin.wasm --out ./dist/test-plugin.zip
```

Copy `dist/test-plugin.zip` to `browser/e2e/tests/fixtures/test-plugin.zip` after rebuilding both WASM and UI. The packager includes `ui/dist/ui.js` and `ui/dist/ui.css` when present.
