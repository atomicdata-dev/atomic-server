# `atomic-server`

[![crates.io](https://img.shields.io/crates/v/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/joepio/atomic?style=social)](https://github.com/joepio/atomic)

_Status: Alpha. Not ready for production time. Prone to changes and corrupt databases when upgrading. [Changelog](https://github.com/joepio/atomic/blob/master/CHANGELOG.md)_

The easiest way to share [Atomic Data](https://docs.atomicdata.dev/) on the web.
`atomic-server` is a graph database server for storing and sharing typed linked data.
Demo on [atomicdata.dev](https://atomicdata.dev)

- No runtime dependencies, fast, runs on all platforms
- Embedded HTTP / HTTPS / HTTP2.0 server. Built-in LetsEncrypt handshake.
- Serialization to JSON, [JSON-AD](https://docs.atomicdata.dev/core/serialization.html#json-ad), and various Linked Data / RDF formats (RDF/XML, N-Triples / Turtle / JSON-LD).
- Dynamic schema validation / type checking using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html)
- Event-sourced versioning / history powered by [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html)
- Pagination, sorting and filtering using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html)
- Authorization (read / write permissions) and Hierarchical structures powered by [Atomic Hierarchy](https://docs.atomicdata.dev/hierarchy.html)
- Invite / sharing system with [Atomic Invites](https://docs.atomicdata.dev/invitations.html)
- Supports querying, sorting and filtering using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html)
- Uses [atomic-data-browser](https://github.com/joepio/atomic-data-browser) as a GUI / front-end, which offers dynamic forms, tables, authentication and more.

Powered by Rust, [atomic-lib](https://crates.io/crates/atomic-lib), [actix-web](https://github.com/actix/actix-web), [sled](https://github.com/spacejam/sled) and [more](Cargo.toml).

## When should you use this

- You want to make (high-value) datasets as easily accessible as possible
- You want to specify and share a common vocabulary / ontology / schema for some specific domain or dataset. Example classes [here](https://atomicdata.dev/classes).
- You want to use and share linked data, but don't want to deal with most of [the complexities of RDF](https://docs.atomicdata.dev/interoperability/rdf.html), SPARQL, Triple Stores, Named Graphs and Blank Nodes.
- You are interested in re-decentralizing the web or want want to work with tech that improves data ownership and interoperability.
- You like living on the edge (this application is not production ready)

```
SUBCOMMANDS:
    export    Create a JSON-AD backup of the store.
    import    Import a JSON-AD backup to the store. Overwrites Resources with same @id.
    run       Starts the server
```

## When _not_ to use this

- If you need stability or reliability, look further (for now).
- You're dealing with non-public / private data. As of now, this server does not have methods to prevent access to content.
- Complex query requirements. Check out NEO4j, Apache Jena or maybe TerminusDB.

## Installation & getting started

You can run `atomic-server` in four ways:

- Install using [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html): `cargo install atomic-server`
- Using docker
- From a published [binary](https://github.com/joepio/atomic/releases)
- From source

### Run using docker

The `dockerfile` is located in the project root, above this `server` folder.

- Run: `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
- If you want to update, run `docker pull joepmeneer/atomic-server` and docker should fetch the latest version.

### Install from source

```sh
# Clone this repoo
git clone git@github.com:joepio/atomic.git
cd atomic/server
# Optional, but recommended: Create a new .env using the template.
cp default.env .env
# Run the server. It creates a store in ~/.config/atomic/db by default
cargo run
# Or tun the extra-cool desktop version with a presence in your app tray
cargo run --features desktop
```

### Troubleshooting during installation

```sh
# If pkg-config or libssl-dev is not installed, make sure to install them
sudo apt-get install -y pkg-config libssl-dev --fix-missing                                                                                                                                                                       10:52:39
```

## Initial setup and configuration

- Visit `http://localhost/setup` to **register your first (admin) user**. You can use an existing Agent, or create a new one.
- The server loads the `.env` from the current path by default. Use the `default.env` from this repo as a template and for reference.
- If you want to run Atomic Server on your own domain, you'll probably want to set `ATOMIC_DOMAIN`, `ATOMIC_HTTPS` and `ATOMIC_EMAIL` in the `.env` (see HTTPS setup below)
- After running the server, check the logs and take note of the `Agent Subject` and `Private key`. You should use these in the [`atomic-cli`](https://crates.io/crates/atomic-cli) and [atomic-data-browser](https://github.com/joepio/atomic-data-browser) clients for authorization.
- A directory is made: `~/.config/atomic`, which stores your newly created Agent keys, your data, the HTTPS certificates and a folder for public static files.

### HTTPS Setup

You'll probably want to make your Atomic Data available through HTTPS.
You can use the embedded HTTPS / TLS setup powered by [LetsEncrypt](https://letsencrypt.org/), [acme_lib](https://docs.rs/acme-lib/0.8.1/acme_lib/index.html) and [rustls](https://github.com/ctz/rustls).
To setup HTTPS, we'll need to set some environment variables.
Open `.env` and set:

```env
ATOMIC_EMAIL=youremail@example.com
ATOMIC_DOMAIN=example.com
ATOMIC_HTTPS=true
```

Run the server: `cargo run`.
Make sure the server is accessible at `ATOMIC_DOMAIN` at port 80, because Let's Encrypt will send an HTTP request to this server's `/.well-known` directory to check the keys.
It will now initialize the certificate.
Read the logs, watch for errors.

HTTPS certificates are automatically renewed when the server is restarted, and the certs are 4 weeks or older.

## Usage

There are three ways to interact with this server:

- **GUI**: Use the `atomic-data-browser` JS frontend by visiting `localhost`.
- **API**: Check out [./example_requests.http](./example_requests.http) for various HTTP requests to the server. Also, [read the docs](https://docs.atomicdata.dev/). You can also try the [react boilerplate](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx:0-1223) to build your own front-end app using [@tomic/lib](https://www.npmjs.com/package/@tomic/lib) and [@tomic/react](https://www.npmjs.com/package/@tomic/react).
- **CLI**: The `atomic-cli` terminal app

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

## Extra commands

The `atomic-server` binary has some extra CLI commands: `import` and `export`.
Run `atomic-server --help` to read more.

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
