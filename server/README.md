# `atomic-server`

[![crates.io](https://meritbadge.herokuapp.com/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

_Status: pre-alpha_

A lightweight HTTP server that shares created Atomic data on the web.

## Progress

- [x] Respond to GET request for individual resources
- [x] URL extension recognition (.json, .ad3, .nt, etc.)
- [x] HTML serialization
- [x] JSON serialization
- [x] JSON-LD serialization
- [x] AD3 serialization
- [ ] RDF (Turtle / N-Triples) serialization
- [x] Basic error handling
- [x] TPF endpoint
- [x] Homepage
- [x] Static asset support for .css / .ico / etc.
- [x] HTTPS (WIP, kind of working)
- [x] Content-type negotiation
- [ ] CSS / design
- [ ] Collections / dynamic resources
- [ ] Write / [Mutations](https://docs.atomicdata.dev/mutations/intro.html) support
- [ ] Auth support (WebID-OICD possibly?)

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

* Run `atomic-server` inside a directory with `/static` folder for files
* If you want to use HTTPS / SSL, set `ATOMIC_CERT_INIT` to `true` and run the server. After that, set it to `false` and set `ATOMIC_HTTPS` to `true`.
* If no `.ad3` store path is given, a new store will be created from memory.

## Running from cargo

You can also install with `cargo install atomic-server`, but this binary will also require:

- the `.env` from this repo, although the defaults should work just fine.
- the `/templates` directory
- the `/static` directory

## Usage

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

### HTTPS / SSL Setup (using LetsEncrypt)

You can use the embedded HTTPS setup, using LetsEncrypt.
This is probably the easiest way to set up `atomic-server`.
To setup HTTPS, we'll need to set some environment variables.
Open `.env` and set:

```env
ATOMIC_EMAIL=youremail@example.com
ATOMIC_DOMAIN=example.com
```

Run the server `cargo run`.
Make sure the server is accessible at your domain, because Let's Encrypt will send a request to this server's `/.well-known` directory, w
It will now initialize the certificate.
Read the logs, watch for errors.

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
