# `atomic-server`

[![crates.io](https://meritbadge.herokuapp.com/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/joepio/atomic?style=social)](https://github.com/joepio/atomic)

_Status: Alpha. Not ready for production time. Prone to changes and corrupt databases when upgrading. [Changelog](https://github.com/joepio/atomic/blob/master/CHANGELOG.md)_

The easiest way to share Atomic Data on the web.
It's a database and a server for storing and sharing typed linked data.
Demo on [atomicdata.dev](https://atomicdata.dev)

- No runtime dependencies, fast, runs on all platforms
- Embedded HTTP / HTTPS / HTTP2.0 server
- Serialization to HTML, JSON, Linked Data (RDF/XML, N-Triples / Turtle / JSON-LD) and [JSON-AD](https://docs.atomicdata.dev/core/serialization.html#json-ad)
- Uses [atomic-data-abrowser](https://github.com/joepio/atomic-data-browser) as front-end.

Powered by Rust, atomic-lib, actix-web, Sled and [more](Cargo.toml).

## When should you use this

- You want to make (high-value) datasets as easily accessible as possible
- You can afford to create or find an Atomic Schema for your dataset (use `atomic-cli new class` for this). Example classes [here](https://atomicdata.dev/classes).
- You want to use and share linked data, but don't want to deal with most of [the complexities of RDF](https://docs.atomicdata.dev/interoperability/rdf.html), SPARQL, Triple Stores, Named Graphs and Blank Nodes.
- You like living on the edge (this application is not production ready)

## Getting started

### Run using docker

The `dockerfile` is located in the project root, above this `server` folder.

- Run: `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
- Take note of the Agent Subject and Private key, you should use these in the [`atomic-cli`](https://crates.io/crates/atomic-cli) and [atomic-data-browser](https://github.com/joepio/atomic-data-browser) clients for authorization.
- If you want to update, run `docker pull joepmeneer/atomic-server` and docker should fetch the latest version.

### Install from source

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

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
# Visit http://localhost
```

### Running from cargo

You can also install with `cargo install atomic-server`, but this binary will also require:

- the `/templates` directory
- the `/static` directory

## Usage

Check out [./example_requests.http](/example_requests.http) for various HTTP requests to the server.

### Set up on own domain

If you want to run Atomic Server on your own VPS + domain, make sure to correctly set the `.env`.
See `default.env` for a template and explanation of variables.

### Use `atomic-cli` as client

`atomic-cli` is a useful terminal tool for interacting with `atomic-server`.
It makes it easy to query and edit Atomic Data from the command line.
[Check it out](https://github.com/joepio/atomic/tree/master/cli).

### Get individual resources

You can fetch individual items by sending a GET request to their URL.

```sh
# Fetch as JSON-AD (de facto standard for Atomic Data)
curl -i -H "Accept: application/ad-json" https://atomicdata.dev/properties/shortname
# Fetch as JSON-LD
curl -i -H "Accept: application/ld+json" https://atomicdata.dev/properties/shortname
# Fetch as JSON
curl -i -H "Accept: application/json" https://atomicdata.dev/properties/shortname
# Fetch as Turtle / N3
curl -i -H "Accept: text/turtle" https://atomicdata.dev/properties/shortname
```

### HTTPS Setup

You'll probably want to make your Atomic Data available through HTTPS.
You can use the embedded HTTPS / TLS setup powered by [LetsEncrypt](https://letsencrypt.org/), [acme_lib](https://docs.rs/acme-lib/0.8.1/acme_lib/index.html) and [rustls](https://github.com/ctz/rustls).
To setup HTTPS, we'll need to set some environment variables.
Open `.env` and set:

```env
ATOMIC_EMAIL=youremail@example.com
ATOMIC_DOMAIN=example.com
```

Run the server `cargo run`.
Make sure the server is accessible at `ATOMIC_DOMAIN` at port 80, because Let's Encrypt will send an HTTP request to this server's `/.well-known` directory to check the keys.
It will now initialize the certificate.
Read the logs, watch for errors.

HTTPS certificates are automatically renewed when the server is restarted, and the certs are 4 weeks or older.

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
