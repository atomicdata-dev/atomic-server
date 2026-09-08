# Atomic-Server Desktop (powered by Tauri)

Desktop release for Atomic-Server.
[Tauri] takes care of native installers, app icons, system tray icons, menu items, self-update ([issue](https://github.com/atomicdata-dev/atomic-server/issues/158)) and more.

```sh
# install tauri
cargo install tauri-cli
# from this directory: run the dev server
cargo tauri dev
# build an installer for your OS
cargo tauri build
```

## Running in development

`cargo tauri dev` starts the front-end for you — `beforeDevCommand` in `tauri.conf.json` runs `pnpm -C browser/data-browser dev:tauri`, and the app points at `localhost:6747` (`devUrl`).
If you only want to work on the _server side_ of things, you can remove `devUrl` in `tauri.conf.json`.

`cargo tauri build` likewise runs `beforeBuildCommand` to produce `browser/data-browser/dist-tauri` before bundling.

### Driving the app from an agent (MCP bridge)

Debug builds register `tauri-plugin-mcp-bridge` on `127.0.0.1:9223`, which lets
an MCP client open documents, type, and read the DOM — enough to test things
like collaborative editing end to end without a person at the keyboard.

The bridge also needs `withGlobalTauri`, which is static config rather than
something `debug_assertions` can gate. Rather than ship it, it lives in a
separate file you opt into:

```sh
cargo tauri dev --config tauri.dev.conf.json
```

Without that flag the plugin still starts, but the webview has no
`window.__TAURI__` for it to talk through. Keep `withGlobalTauri` out of
`tauri.conf.json`: this app runs with `csp: null` and renders data from drives
the user may not control, so exposing the Tauri API to page content in shipped
builds widens a surface that is already wide.

The channel is unauthenticated — anything that can reach the port can execute
JS in the webview — which is why it binds to loopback rather than the plugin's
default `0.0.0.0`.

### Environment overrides are baked in at build time

`beforeBuildCommand` is a normal vite production build, so it reads `.env` and
`.env.local` — but *not* `.env.development*`. Put local control-plane URLs
(`VITE_MANAGED_PORTAL_URL`, `VITE_MANAGED_API_BASE`) in
`browser/data-browser/.env.development.local`. In `.env.local` they end up
compiled into the shipped app, pointing it at a dev machine's ports.

### macOS: repeated "wants to use your confidential information" prompts

The app stores the agent's keypair as a **non-extractable** `CryptoKey` in
IndexedDB (`helpers/agentStorage.ts`). WebKit implements that by wrapping the
key under a master key it keeps in the login keychain — the item named
"Atomic Server WebCrypto Master Key". Reading it requires a keychain ACL match
against the app's code signature.

An **ad-hoc, linker-signed** binary has no stable identity for that ACL to
trust — its code identity is a hash of the binary itself, so macOS re-asks and
"Always Allow" is void as soon as you relink. Hence `signingIdentity` in
`tauri.conf.json`: bundles are signed with the Developer ID certificate, whose
requirement (identifier plus team `Q9WPWRTU7G`) survives rebuilds, version
bumps and reinstalls. One "Always Allow" then holds forever, for users on every
update as much as for us.

Without that certificate in your keychain, `cargo tauri build` fails with `no
identity found`. Override with codesign's ad-hoc identity:

```sh
APPLE_SIGNING_IDENTITY=- cargo tauri build
```

`APPLE_SIGNING_IDENTITY` takes precedence over the config value, which is also
how `tauri-release.yml` feeds in the certificate from repository secrets, and
how its secret-less runs fall back to ad-hoc.

`cargo tauri dev` needs the same identity and tauri never signs it, so
`desktop/.cargo/config.toml` points cargo's target runner at
`scripts/sign-dev-binary.sh`, which signs the binary between the link and the
launch (`cargo tauri dev` shells out to `cargo run`, so a runner is the only
hook available). Dev builds get no hardened runtime and keep `get-task-allow`,
so lldb still attaches. Without the certificate the runner is a no-op and the
app runs ad-hoc, as before. It costs ~2s per launch on the 168MB debug binary.

Note what does *not* work: setting the keychain item to "Allow all
applications". Access is gated twice, on the item's ACL and on its **partition
list** of code identities, and the Keychain Access UI only edits the first. An
ad-hoc binary contributes `cdhash:<hash of this exact build>` to that list — so
each "Always Allow" pinned the build being replaced, and the item accumulated
55 dead cdhashes. A Developer ID signature contributes `teamid:Q9WPWRTU7G`,
which every later build shares.

## Limitations

- No way to pass flags to `atomic-sever` using the Tauri executable (although you can set ENV variables)
- No HTTPS support

### Error reporting in official packages

The release workflow enables Sentry for the embedded WebView on every platform,
including Android and iOS. Tag builds use `production`; manual workflow builds
use `staging`. Reports carry the app version and source commit. JavaScript/React
errors and sidebar feedback are covered; native process crashes are not covered
by this browser SDK. Local builds can opt in with `VITE_SENTRY_DSN` and
`VITE_SENTRY_ENVIRONMENT`. See the SaaS `SENTRY.md` runbook for receipt verification.

Android launcher images are generated from `brand/src/atomic-mark.svg` by
`node brand/generate.mjs`, including adaptive foregrounds at every density.

### Automatic Cloud Vault backup

With a linked, eligible account, the open local drive is enrolled and backed up
without a setup click. Tauri's embedded-node drives count as local data; unrelated
remote drives are excluded unless already enrolled with this account. The personal
drive is retried after startup too, so late account linking does not require a restart.
Explicit backup opt-outs and account eligibility checks remain authoritative.

The browser and Tauri watcher uses incremental packs: 5 seconds after editing
stops, or at most 30 seconds during sustained editing. Switching drives preserves
queued work. Foregrounding/reconnecting retries immediately; a 60-second check
also catches native-node changes and late account availability. Unchanged drives
upload no object. These timers run only while the app runtime can execute; they
are not an Android/iOS OS background service. Manual backup remains a retry option.
