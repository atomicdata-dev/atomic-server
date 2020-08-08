# `atomic-server`

_Status: pre-alpha_

A lightweight HTTP server that shares created Atomic data on the web.

- [x] Respond to GET request for individual resources
- [ ] Content-type negotiation
- [x] URL extension recognition
- [x] HTML serialization
- [x] JSON serialization
- [x] AD3 serialization
- [ ] TPF endpoint
- [ ] Homepage
- [ ] HTTPS
- [ ] Write / Mutations support
- [ ] Collections / dynamic resources

## Usage

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
