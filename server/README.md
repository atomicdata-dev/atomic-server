# `atomic-server`

_Status: pre-alpha_

A lightweight HTTP server that shares created Atomic data on the web.

## Progress

- [x] Respond to GET request for individual resources
- [x] URL extension recognition
- [x] HTML serialization
- [x] JSON serialization
- [x] AD3 serialization
- [x] Basic error handling
- [x] TPF endpoint
- [x] Homepage
- [x] Static asset support for .css / .ico / etc.
- [ ] CSS / design
- [ ] Content-type negotiation
- [ ] Collections / dynamic resources
- [ ] HTTPS
- [ ] Write / [Mutations](https://docs.atomicdata.dev/mutations/intro.html) support
- [ ] Auth support (WebID-OICD possibly?)

## Install from source

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

```sh
git clone git@github.com:joepio/atomic.git
cd atomic/server
# Create a new .env using the template
cp default.env .env
# Run the server. It loads the .ad3 store that you point towards
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
