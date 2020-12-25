# `atomic-server`

[![crates.io](https://meritbadge.herokuapp.com/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

_Status: alpha, not ready for production usage. Can panic at runtime._

The easiest way to share Atomic Data on the web. Demo on [atomicdata.dev](https://atomicdata.dev)

- No runtime dependencies, fast, runs on all platforms (including on your Raspberry Pi)
- Embedded HTTP / HTTPS / HTTP2.0 server
- Serialization to HTML, JSON, Linked Data (RDF/XML, N-Triples / Turtle / JSON-LD) and AD3

Powered by Rust, atomic_lib, actix-web, Sled and [more](cargo.toml).

## Progress

- [x] Respond to GET request for individual resources
- [x] HTML serialization
- [x] JSON serialization
- [x] JSON-LD serialization
- [x] AD3 serialization
- [x] RDF (Turtle / N-Triples) serialization
- [x] Basic error handling
- [x] TPF endpoint
- [x] Homepage
- [x] Static asset support for .css / .ico / etc.
- [x] HTTPS (WIP, kind of working)
- [x] Content-type negotiation
- [x] Basic design / use CSS framework
- [x] Validation endpoint
- [x] Atomic Commits (#16, #24)
- [x] Eliminate all preventable runtime panics (most already done)
- [x] URL extension recognition (.json, .ad3, .nt, etc.)
- [x] Collections / dynamic resources #17
- [ ] Authentication #13
- [ ] Authorization model (implemented for write, not read)
- [ ] Be able to manage the AtomicData.dev website without git (cli integration, implement required endpoints) [#6](https://github.com/joepio/atomic/issues/6)
- [ ] Plugin / apps #

## Install from source

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

```sh
git clone git@github.com:joepio/atomic.git
cd atomic/server
# Create a new .env using the template
cp default.env .env
# Run the server. It creates a store in ~/.config/atomic/db by default
cargo run
# Visit http://localhost:8080/test
```

## Running from cargo

You can also install with `cargo install atomic-server`, but this binary will also require:

- the `/templates` directory
- the `/static` directory
- the `.env` from this repo, (if you need modifications).

## Usage

Check out [./example_requests.http](/example_requests.http) for various HTTP requests to the server.

### Get individual resources

You can fetch individual items by sending a GET request to their URL.

```sh
# Fetch as AD3 triples
curl -i -H "Accept: application/ad3-ndjson" http://127.0.0.1:8081/test
# Fetch as JSON-LD
curl -i -H "Accept: application/ld+json" http://127.0.0.1:8081/test
# Fetch as JSON
curl -i -H "Accept: application/json" http://127.0.0.1:8081/test
# Fetch as Turtle / N3
curl -i -H "Accept: text/turtle" http://127.0.0.1:8081/test
```

### Query the store with Triple Pattern Fragments

```sh
# Fetch as AD3 triples
curl -i -H "Accept: application/ad3-ndjson" "http://127.0.0.1:8081/tpf?subject=&property=&value=test"
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

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
