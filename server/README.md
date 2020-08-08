# `atomic-server`

A lightweight HTTP server that shares created Atomic data on the web.

For setting up the server:

```sh
# Create a new .env using the template
cp default.env .env
# Run the server. It loads the .ad3 store that you point towards
atomic-server
# Visit http://localhost:8080/test
```

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
