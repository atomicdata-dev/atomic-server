# Atomic Plugins

Atomic Plugins are applications that can run inside of an Atomic Server.
They enhance the functionality of an Atomic Server by extending one or more classes.

For example they can be used to create more restrictive requirements for classes, like requiring names to start with an uppercase letter.
They can also add dynamic properties to classes that get populated each time the resource is fetched.

Plugins can be created in any programming language that compiles to Wasm.
For more information on how to create a plugin, see [Creating Plugins](plugins/creating-plugins.md).

## Installing a plugin

To install a plugin you need to have write access to the drive that the plugin will be installed on.
Navigate to the drive and click on the 'Upload Plugin' button.
Select your plugin zip file.
You will see a description of the plugin, any permissions it requires and a config field.
Edit the config if needed and click 'Install'.
You can change the config at any time once the plugin is installed.

## Giving your plugin access to resources

By default plugins do not have access to any resources unless they have the `full-drive-access` permission.
To add access to specific resources (and their children) navigate to the plugin page and add the resource in the 'Assign Rights' section.

<!-- ## Hooks

### BeforeCommit

Is run before a Commit is applied.
Useful for performing authorization or data shape checks.

## Wasm class extenders

Atomic Server can load class extenders that are compiled to WASM + WASI Preview 2 (aka wasip2).
Every extender implements the [`class-extender.wit`](../../lib/wit/class-extender.wit) world and exports:

- `class-url` – the Subject URL of the class to extend
- `on-resource-get`
- `before-commit`
- `after-commit`

Handlers receive JSON-AD payloads that describe the Resource or Commit they should work with and can return an updated JSON-AD document. See the WIT file for the exact record layouts.

### Installing a WASM class extender

1. Build a component that targets `wasm32-wasip2`. Use `wit-bindgen` or `cargo component` to satisfy the interface defined in `lib/wit/class-extender.wit`.
2. Copy the resulting `.wasm` file into the `wasm-class-extenders/` directory inside your Atomic data directory (next to the sled store).
3. Restart `atomic-server` (or recreate the `Db`) so it scans the folder and instantiates your component.

All `.wasm` files in that folder are loaded on startup. Errors are logged but do not prevent the server from running, making it safe to iterate on plugins.

### Sample Wasm extender

See `wasm-plugins/examples/random-folder-extender` for a minimal Rust project that implements the `class-extender` WIT interface. It appends a random suffix to the `name` property of every `https://atomicdata.dev/classes/Folder` resource whenever it is fetched. Build it with `cargo component build --release -p random-folder-extender --target wasm32-wasip2` and copy the resulting `.wasm` into your `wasm-class-extenders/` directory to try it out. -->



## Integration discovery preferences

Open **Settings → Integration** to choose which plugins appear on the
**Integrations** page:

- **Show API plugins** displays the LocalThought API catalog.
- **Show experimental plugins** displays bundled experimental integrations and
  unverified community plugins.

Both options are unchecked by default and work independently. When a category
is hidden, the Integrations page links to Settings so you can consider enabling
it. Hidden catalogs are not fetched.

These preferences are saved as boolean properties on your private Atomic drive,
using its ontology, and follow that drive through normal Atomic sync. They are
personal preferences, not settings on the currently open shared workspace.
Turning them off hides discovery listings; it does not remove existing
connections or stop their automations. Enabling a category does not certify its
plugins or grant permission to run them.
