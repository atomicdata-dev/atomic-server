# `atomic-server`

[![crates.io](https://img.shields.io/crates/v/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/joepio/atomic?style=social)](https://github.com/joepio/atomic)

_Status: Alpha. Not ready for production time. Prone to changes and corrupt databases when upgrading. [Changelog](https://github.com/joepio/atomic/blob/master/CHANGELOG.md)_

The easiest way to share [Atomic Data](https://docs.atomicdata.dev/) on the web.
`atomic-server` is a graph database server for storing and sharing typed linked data.
Demo on [atomicdata.dev](https://atomicdata.dev)

- ⚛️  **Dynamic schema validation** / type checking using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html). Combines safety of structured data with the
- 🚀  **Fast** (1ms responses on my laptop)
- 🪶  **Lightweight** (15MB binary, no runtime dependencies)
- 💻  **Runs everywhere** (linux, windows, mac, arm)
- 🌐  **Embedded server** with support for HTTP / HTTPS / HTTP2.0 and Built-in LetsEncrypt handshake.
- 🎛️  **Browser GUI included** powered by [atomic-data-browser](https://github.com/joepio/atomic-data-browser). Features dynamic forms, tables, authentication, theming and more.
- ↩️  **Event-sourced versioning** / history powered by [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html)
- 🧰  **Many serialization options**: to JSON, [JSON-AD](https://docs.atomicdata.dev/core/serialization.html#json-ad), and various Linked Data / RDF formats (RDF/XML, N-Triples / Turtle / JSON-LD).
- 🔎  **Full-text search** with fuzzy search and various operators, often <3ms responses.
- 📖  **Pagination, sorting and filtering** using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html)
- 🔐  **Authorization** (read / write permissions) and Hierarchical structures powered by [Atomic Hierarchy](https://docs.atomicdata.dev/hierarchy.html)
- 📲  **Invite and sharing system** with [Atomic Invites](https://docs.atomicdata.dev/invitations.html)

Powered by Rust, [atomic-lib](https://crates.io/crates/atomic-lib), [actix-web](https://github.com/actix/actix-web), [sled](https://github.com/spacejam/sled), [tantivy](https://github.com/quickwit-inc/tantivy) and [more](Cargo.toml).

## When should you use this

- You want to make (high-value) datasets as easily accessible as possible
- You want to specify and share a common vocabulary / ontology / schema for some specific domain or dataset. Example classes [here](https://atomicdata.dev/classes).
- You want to use and share linked data, but don't want to deal with most of [the complexities of RDF](https://docs.atomicdata.dev/interoperability/rdf.html), SPARQL, Triple Stores, Named Graphs and Blank Nodes.
- You are interested in re-decentralizing the web or want want to work with tech that improves data ownership and interoperability.
- You like living on the edge (this application is not production ready)

## CLI commands

```
FLAGS:
    -h, --help       Prints help information
    -i, --init       Recreates the `/setup` Invite for creating a new Root User. Also re-runs various populate commands,
                     and re-builds the index.
    -r, --reindex    Rebuilds the index (can take a while for large stores).
    -V, --version    Prints version information

SUBCOMMANDS:
    export    Create a JSON-AD backup of the store.
    help      Prints this message or the help of the given subcommand(s)
    import    Import a JSON-AD backup to the store. Overwrites Resources with same @id.
```

## When _not_ to use this

- If you need stability or reliability, look further (for now).
- You're dealing with non-public / private data. As of now, this server does not have methods to prevent access to content.
- Complex query requirements. Check out NEO4j, Apache Jena or maybe TerminusDB.

## Installation & getting started

You can run `atomic-server` in four ways:

- From a published [binary](https://github.com/joepio/atomic/releases) (probably the quickest)
- Using docker
- Using [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) from crates.io: `cargo install atomic-server`
- Manually from source

When you're running `atomic-server`, go to [Initial setup and configuration](#Initial-setup-and-configuration)

### Run using docker

The `dockerfile` is located in the project root, above this `server` folder.

- Run: `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
- If you want to update, run `docker pull joepmeneer/atomic-server` and docker should fetch the latest version.

### Install from source

```sh
# Clone this repoo
git clone git@github.com:joepio/atomic-data-rust.git
cd atomic-data-rust/server
# Optional, but recommended: Create a new .env using the template.
cp default.env .env
# Run the server. It creates a store in ~/.config/atomic/db by default
cargo run
# Or tun the extra-cool desktop version with a presence in your app tray
cargo run --features desktop
# If you don't need HTTPS (or don't have OpenSSL available on your device)
cargo run --no-default-features
```

Troubleshooting compiling from source:

```sh
# If pkg-config or libssl-dev is not installed, make sure to install them
sudo apt-get install -y pkg-config libssl-dev --fix-missing
```

## Initial setup and configuration

- You can configure the server by passing arguments (see `atomic-server --help`), or by setting ENV variables.
- The server loads the `.env` from the current path by default. Create a `.env` file from the default template in your current directory with `atomic-server setup-env`.
- After running the server, check the logs and take note of the `Agent Subject` and `Private key`. You should use these in the [`atomic-cli`](https://crates.io/crates/atomic-cli) and [atomic-data-browser](https://github.com/joepio/atomic-data-browser) clients for authorization.
- A directory is made: `~/.config/atomic`, which stores your newly created Agent keys, your data, the HTTPS certificates and a folder for public static files.
- Visit `http://localhost/setup` to **register your first (admin) user**. You can use an existing Agent, or create a new one.

### HTTPS Setup

You'll probably want to make your Atomic Data available through HTTPS.
You can use the embedded HTTPS / TLS setup powered by [LetsEncrypt](https://letsencrypt.org/), [acme_lib](https://docs.rs/acme-lib/0.8.1/acme_lib/index.html) and [rustls](https://github.com/ctz/rustls).

You can do this by passing these flags:

Run the server: `atomic-server --https --email some@example.com --domain example.com`.

You can also set these things using a `.env` or by setting them some other way.

Make sure the server is accessible at `ATOMIC_DOMAIN` at port 80, because Let's Encrypt will send an HTTP request to this server's `/.well-known` directory to check the keys.
It will now initialize the certificate.
Read the logs, watch for errors.

HTTPS certificates are automatically renewed when the server is restarted, and the certs are 4 weeks or older.
They are stored in your `.config/atomic/` dir.

## Usage

There are three ways to interact with this server:

- **GUI**: Use the [`atomic-data-browser`](https://github.com/joepio/atomic-data-browser) JS frontend by visiting `localhost`.
- **API**: Check out [./example_requests.http](./example_requests.http) for various HTTP requests to the server. Also, [read the docs](https://docs.atomicdata.dev/). You can also try the [react boilerplate](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx:0-1223) to build your own front-end app using [@tomic/lib](https://www.npmjs.com/package/@tomic/lib) and [@tomic/react](https://www.npmjs.com/package/@tomic/react).
- **CLI**: The [`atomic-cli`](https://crates.io/crates/atomic-cli/0.24.2) terminal app

### Use `atomic-cli` as client

`atomic-cli` is a useful terminal tool for interacting with `atomic-server`.
It makes it easy to query and edit Atomic Data from the command line.
[Check it out](https://github.com/joepio/atomic/tree/master/cli).

### API

You can fetch individual items by sending a GET request to their URL.

```sh
# Fetch as JSON-AD (de facto standard for Atomic Data)
curl -i -H "Accept: application/ad+json" https://atomicdata.dev/properties/shortname
# Fetch as JSON-LD
curl -i -H "Accept: application/ld+json" https://atomicdata.dev/properties/shortname
# Fetch as JSON
curl -i -H "Accept: application/json" https://atomicdata.dev/properties/shortname
# Fetch as Turtle / N3
curl -i -H "Accept: text/turtle" https://atomicdata.dev/properties/shortname
```

Check out [./example_requests.http](/example_requests.http) for more things that you can do.

## Testing

```sh
# This also makes sure that cli and server work, plus it test the db feature
cargo test --all
```

## Performance benchmarking

```sh
# Install drill
cargo install drill
drill -b benchmark.yml --stats
```

## FAQ

### I lost the key / secret to my Root Agent, and the `/setup` invite is no longer usable! What now?

You can run `atomic-server --init` to recreate the `/setup` invite. It will be reset to `1` usage.

### How do I migrate my data to a new domain?

There are no helper functions for this, but you could `atomic-server export` your JSON-AD, and find + replace your old domain with the new one.
This could especially be helpful if you're running at `localhost` and want to move to a live server.

### How do I reset my database?

Remove the `db` folder in your `atomic` config: `rm -rf ~/.config/atomic/db`.

### How do I make my data private, yet available online?

This is not yet possible. See [#13](https://github.com/joepio/atomic-data-rust/issues/13).

### Collections are empty / TPF is not working

You might have a problem with your index. Try reindexing using `atomic-server --reindex`.

### I get a `failed to retrieve` error when opening

Try re-initializing atomic server `atomic-server --initialize`.
