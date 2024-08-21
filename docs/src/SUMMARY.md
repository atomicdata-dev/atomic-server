## Table of contents

# What is Atomic Data

- [Atomic Data Overview](atomic-data-overview.md)
  - [Motivation](motivation.md)
  - [Strategy, history and roadmap](roadmap.md)
  - [When (not) to use it](when-to-use.md)

# AtomicServer

- [AtomicServer](atomic-server.md)
  - [When (not) to use it](atomicserver/when-to-use.md)
  - [Installation](atomicserver/installation.md)
  - [Using the GUI](atomicserver/gui.md)
    - [Tables](atomicserver/gui/tables.md)
  - [API](atomicserver/API.md)
  - [Creating a JSON-AD file](create-json-ad.md)
  - [FAQ & troubleshooting](atomicserver/faq.md)
- [Clients / SDKs](tooling.md)
  - [Javascript](js-sdks.md)
    - [@tomic/lib](js.md)
      - [Store](js-lib/store.md)
      - [Agent](js-lib/agent.md)
      - [Resource](js-lib/resource.md)
      - [Collection](js-lib/collection.md)
    - [@tomic/react](usecases/react.md)
      - [useStore](react/useStore.md)
      - [useResource](react/useResource.md)
      - [useValue](react/useValue.md)
      - [useCollection](react/useCollection.md)
      - [useServerSearch](react/useServerSearch.md)
      - [useCurrentAgent](react/useCurrentAgent.md)
      - [useCanWrite](react/useCanWrite.md)
      - [Image](react/Image.md)
      - [Examples](react/examples.md)
    - [@tomic/svelte](svelte.md)
      - [Image](svelte/image.md)
    - [JS CLI](js-cli.md)
  - [Rust](rust-lib.md)
    - [Rust lib](rust-lib.md)
    - [Rust CLI](rust-cli.md)

# Guides

- [Build a portfolio using Astro and Atomic Server](astro-guide/1-index.md)
  - [Setup](astro-guide/2-setup.md)
  - [Frontend setup](astro-guide/3-frontend-setup.md)
  - [Basic data model](astro-guide/4-basic-data-model.md)
  - [Creating homepage data](astro-guide/5-creating-homepage-data.md)
  - [Generating types](astro-guide/6-generating-types.md)
  - [Fetching data](astro-guide/7-fetching-data.md)
  - [Using ResourceArray to display a list of projects](astro-guide/8-pojects.md)
  - [Using Collections to build the blogs page](astro-guide/9-blogs.md)
  - [Using the search API to build a search bar](astro-guide/10-search.md)

# Specification

- [Atomic Data Core](core/concepts.md)

  - [Serialization](core/serialization.md)
  - [JSON-AD](core/json-ad.md)
  - [Querying](core/querying.md)
  - [Paths](core/paths.md)
  - [Schema](schema/intro.md)
    - [Classes](schema/classes.md)
    - [Datatypes](schema/datatypes.md)
    - [FAQ](schema/faq.md)

- [Atomic Data Extended](extended.md)
  - [Agents](agents.md)
  - [Hierarchy and authorization](hierarchy.md)
  - [Authentication](authentication.md)
  - [Invitations and sharing](invitations.md)
  - [Commits (writing data)](commits/intro.md)
    - [Concepts](commits/concepts.md)
    - [Compared to](commits/compare.md)
  - [WebSockets](websockets.md)
  - [Endpoints](endpoints.md)
  - [Collections, filtering, sorting](schema/collections.md)
  - [Uploading and downloading files](files.md)

# Use Atomic Data

- [Interoperability and comparisons](interoperability/intro.md)
  - [Create & publish Atomic Data](atomizing.md)
  - [Upgrade your existing project](interoperability/upgrade.md)
  - [RDF](interoperability/rdf.md)
  - [Solid](interoperability/solid.md)
  - [JSON](interoperability/json.md)
  - [IPFS](interoperability/ipfs.md)
  - [SQL](interoperability/sql.md)
  - [Graph Databases](interoperability/graph-database.md)
- [Potential use cases](usecases/intro.md)
  - [As a Headless CMS](usecases/headless-cms.md)
  - [Personal Data Store](usecases/personal-data-store.md)
  - [Artificial Intelligence](usecases/ai.md)
  - [E-commerce & marketplaces](usecases/e-commerce.md)
  - [Surveys](usecases/surveys.md)
  - [Verifiable Credentials](usecases/verifiable-credentials.md)
  - [Data Catalog](usecases/data-catalog.md)
  - [Education](usecases/education.md)
  - [Food labels](usecases/food-labels.md)

---

[Acknowledgements](acknowledgements.md) |
[Newsletter](newsletter.md) |
[Get involved](get-involved.md)
