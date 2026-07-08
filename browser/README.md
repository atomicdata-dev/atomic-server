![Atomic Data Browser](./logo.svg)

[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Create, share, fetch and model linked [Atomic Data](https://atomicdata.dev)!
This repo consists of three components: a javascript / typescript library, a react library, and a complete GUI: Atomic-Data Browser.

## [`atomic-data-browser`](data-browser/README.md)

A GUI for viewing, editing and browsing Atomic Data.
Designed for interacting with [atomic-server](https://github.com/atomicdata-dev/atomic-data-rust/).

**demo on [atomicdata.dev](https://atomicdata.dev)**

<https://user-images.githubusercontent.com/2183313/139728539-d69b899f-6f9b-44cb-a1b7-bbab68beac0c.mp4>

```sh
# To run, simply run the following commands:
pnpm install # install dependencies
pnpm start # run the server!
# visit http://localhost:6747
```

[→ Read more](data-browser/README.md)

## [`@tomic/lib`](lib/README.md)

<a href="https://www.npmjs.com/package\/@tomic/lib" target="_blank">
  <img src="https://img.shields.io/npm/v/@tomic/lib?color=cc3534" />
</a>
<a href="https://www.npmjs.com/package/@tomic/lib" target="_blank">
  <img src="https://img.shields.io/npm/dm/@tomic/lib?color=%2344cc10" />
</a>
<a href="https://bundlephobia.com/result?p=@tomic/lib" target="_blank">
  <img src="https://img.shields.io/bundlephobia/min/@tomic/lib">
</a>

Library with `Store`, `Commit`, `JSON-AD` parsing, and more.

[**docs**](https://docs.atomicdata.dev/js.html)

[→ Read more](lib/README.md)

## [`@tomic/react`](react/README.md)

<a href="https://www.npmjs.com/package/@tomic/react" target="_blank">
  <img src="https://img.shields.io/npm/v/@tomic/react?color=cc3534" />
</a>
<a href="https://www.npmjs.com/package/@tomic/react" target="_blank">
  <img src="https://img.shields.io/npm/dm/@tomic/react?color=%2344cc10" />
</a>
<a href="https://bundlephobia.com/result?p=@tomic/react" target="_blank">
  <img src="https://img.shields.io/bundlephobia/min/@tomic/react">
</a>

React library with many useful hooks for rendering and editing Atomic Data.

[**demo + template on codesandbox**](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx:0-1223)

[**docs**](https://docs.atomicdata.dev/usecases/react.html)

[→ Read more](react/README.md)

## DevTools Console Helpers

In dev mode, `window.devtools` exposes diagnostics for inspecting state across persistence layers. Run `devtools.help()` in the browser console for the list.

| call                         | what it does                                                                                                |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `devtools.inspect(subject?)` | JS store + WASM/OPFS + server HTTP GET, side-by-side. Defaults to the URL's `?subject=` (or current drive). |
| `devtools.opfsList(prefix?)` | Subjects in the WASM DB (default prefix `did:ad:`)                                                          |
| `devtools.wsLog(n?)`         | `console.table` of the last N commit log entries                                                            |
| `devtools.problems()`        | Resources currently loading, errored, or new                                                                |
| `devtools.forcePut(subject)` | Re-serialize a JS-store resource into OPFS with round-trip verification                                     |

Source: `data-browser/src/helpers/devtools.ts`.

## Also check out

- [atomic-data-rust](https://github.com/atomicdata-dev/atomic-data-rs), a rust [**library**](https://crates.io/crates/atomic-lib), [**server**](https://crates.io/crates/atomic-server) and [**cli**](https://crates.io/crates/atomic-cli) for Atomic Data.
- [sign up to the Atomic Data Newsletter](http://eepurl.com/hHcRA1)

## Contribute

Issues and PR's are welcome!
And join our [Discord][discord-url]!
See [Contributing.md](CONTRIBUTING.md)

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
