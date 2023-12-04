![Atomic Data](src/assets/atomic_data_logo_stroke.svg)

# `atomic-data-docs`

_Atomic Data is a specification for sharing, modifying and modeling graph data._

View it on [docs.atomicdata.dev](https://docs.atomicdata.dev).
If you're looking for **implementations of Atomic Data**, check out [atomic-server](https://github.com/atomicdata-dev/atomic-server) (server + cli + lib written in Rust) and [atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser) (react / typescript).

## About this repo

This repository holds the markdown book for the Atomic Data standard.
It serves two purposes:

- A central hub for **written content** such as documentation, the specification, tutorials and guides.
- A place to **discuss the specification** - that should happen in this issue tracker.

## Running locally

You can run it locally using [mdBook](https://github.com/rust-lang/mdBook)

```sh
# This requires at least Rust 1.39 and Cargo to be installed. Once you have installed Rust, type the following in the terminal:
cargo install mdbook
# Install mdbook-linkcheck to prevent broken links in your markdown.
cargo install mdbook-linkcheck
# Serve at localhost:3000, updates when files change.
mdbook serve
```

Publishing is done with Github actions - simply push the master branch.

## Contributing

Add an issue or open a PR!
All thoughts are welcome.
Also, check out the [Discord](https://discord.gg/a72Rv2P).
