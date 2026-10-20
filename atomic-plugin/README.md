# atomic-plugin

A helper library that removes a lot of the boilerplate when building AtomicServer Wasm plugins.

## Class Extenders

Atomic Data Classextenders are plugins that can modify the behavior of an Atomic Data class.
For example you might want to add some custom verification logic to a class.
A class extender is a server module on the host ABI (`atomic-host/wit/host.wit`, world `server-module`).
It reads and writes as its Installation's agent: `get_resource`, `query`, `commit` (planned as `store.apply`), `get_config`
and `fetch` (by manifest operation, `net.fetch`) go through the same checks as for any app.

## How to use

Simply implement the `ClassExtender` trait on a struct and export it using the `export_plugin!` macro.

```rust
use atomic_plugin::{ClassExtender, Commit, Resource};

struct MyExtender;

impl ClassExtender for MyExtender {
  // REQUIRED: Returns the class that this class extender applies to.
    fn class_url() -> Vec<String> {
        vec!["https://atomicdata.dev/classes/Folder".to_string()]
    }

    // Prevent commits where the name contains "Tailwind CSS".
    fn before_commit(commit: &Commit, _snapshot: &Resource, _is_new: bool) -> Result<(), String> {
        let Some(set) = &commit.set else {
            return Ok(());
        };

        let Some(name) = set.get("https://atomicdata.dev/properties/name".to_string()).and_then(|val| val.as_str()) else {
            return Ok(());
        };

        if name.contains("Tailwind CSS") {
            return Err("Tailwind CSS is not allowed".into());
        }

        Ok(())
    }
}

atomic_plugin::export_plugin!(MyExtender);
```
