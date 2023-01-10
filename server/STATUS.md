# Atomic-Server status & Feature stability

If you're contemplating to use Atomic-Server in a prodcution environment, you'll want to know to what extend you could rely on this project. 
Some features are prone to change, whilst others are already fully working as intended.
This document describes the current status of Atomic-Server, and specifically which features are stable, and which are not.

## Stable

These features are very unlikely to be significantly altered until V1.0. They will also not be dropped. 

- HTTP Resource fetching.
- JSON-AD serialization / parsing.
- TLS / HTTPS setup. 
- WebSockets. Some features may be added, but for most use cases the current implementation works great.
- Commits. There may be changes in the signature algorithm or the likes, but I don't expect much changes.
- Storage + migration system. Upgrading your Atomic-Server should not lead to data loss. Migrations are fully automated.

## Likely to change

- Endpoint API. Currently only supports GET requests. 
- Collections / Queries. Relatively stable, but still lacks some important features (like having multiple filters in one Query).
- Cookie Authentication. 
- Document editor, see [milestone](https://github.com/atomicdata-dev/atomic-data-browser/milestone/2).
- Table editor, see [milestone](https://github.com/atomicdata-dev/atomic-data-browser/milestone/3).
- URL requirements for new URLS, see [issue](https://github.com/atomicdata-dev/atomic-data-rust/issues/556)
- Full text search. Improvements to sorting algorithm and adding more filter options is likely.

## Experimental

- Plugin system. All APIs related to this are very likely to change. See [issue](https://github.com/atomicdata-dev/atomic-data-rust/issues/73)
- Chat rooms. They work, but expect serious changes.
