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

## Install

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

```sh
git clone git@github.com:joepio/atomic.git
cd atomic/server
# Install atomic-server to path
cargo install --path ./
# Create a new .env using the template
cp default.env .env
# Run the server. It loads the .ad3 store that you point towards
atomic-server
# Visit http://localhost:8080/test
```

You can also install with `cargo install atomic-server`, but you currently need the `.env` from this repo.
