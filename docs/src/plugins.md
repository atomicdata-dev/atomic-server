# Atomic Plugins

Atomic Plugins are applications that can run inside of an Atomic Server.
They enhance the functionality of an Atomic Server.
For example, they can:

- Extend existing resources (e.g. automatic translations)
- Provide new endpoints (maybe even ports?) with custom functionality (e.g. full text search for pod data, an e-mail server)
- Periodically execute some code (e.g. fetch new data from a source)
- Add datatypes and validation

## The Plugin Resource

A Plugin itself is a Resource: it is described using Atoms.
The most important Atom for a Plugin, is the `wasm` property: this contains the actual code.
Other properties include:

- `name`
- `description`
- `author`

## Registering a plugin

When a plugin is installed, the Server needs to be aware of when the functionality of the plugin needs to be called:

- Periodically (if so, when?)
- On a certain endpoint (which endpoint? One or multiple?)
- As a middleware when (specific) resources are created / read / updated.

## Hooks

### BeforeCommit

Is run before a Commit is applied.
Useful for performing authorization or data shape checks.
