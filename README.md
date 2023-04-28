![AtomicServer](./logo.svg)

[![crates.io](https://img.shields.io/crates/v/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/atomicdata-dev/atomic-server?style=social)](https://github.com/atomicdata-dev/atomic-server)

**Create, share, fetch and model [Atomic Data](https://docs.atomicdata.dev)!
AtomicServer is a lightweight, yet powerful CMS / Graph Database.
Demo on [atomicdata.dev](https://atomicdata.dev)
This repo also includes the [`atomic_lib`](lib/README.md) Rust library and [`atomic-cli`](cli/README.md).**

_Status: alpha. [Breaking changes](CHANGELOG.md) are expected until 1.0._

<!-- We re-use this table in various places, such as README.md and in the docs repo. Consider this the source. -->
- 🚀  **Fast** (less than 1ms median response time on my laptop), powered by [actix-web](https://github.com/actix/actix-web) and [sled](https://github.com/spacejam/sled)
- 🪶  **Lightweight** (8MB download, no runtime dependencies)
- 💻  **Runs everywhere** (linux, windows, mac, arm)
- ⚛️  **Dynamic schema validation** / type checking using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html).
- 🌐  **Embedded server** with support for HTTP / HTTPS / HTTP2.0 and Built-in LetsEncrypt handshake.
- 🎛️  **Browser GUI included** powered by [atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser). Features dynamic forms, tables, authentication, theming and more.
- 💾  **Event-sourced versioning** / history powered by [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html)
- 🔄  **Synchronization using websockets**: communicates state changes with a client.
- 🧰  **Many serialization options**: to JSON, [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html), and various Linked Data / RDF formats (RDF/XML, N-Triples / Turtle / JSON-LD).
- 🔎  **Full-text search** with fuzzy search and various operators, often <3ms responses. Powered by [tantivy](https://github.com/quickwit-inc/tantivy).
- 📖  **Pagination, sorting and filtering** queries using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html).
- 🔐  **Authorization** (read / write permissions) and Hierarchical structures powered by [Atomic Hierarchy](https://docs.atomicdata.dev/hierarchy.html)
- 📲  **Invite and sharing system** with [Atomic Invites](https://docs.atomicdata.dev/invitations.html)
- 📂  **File management**: Upload, download and preview attachments.
- 🖥️  **Desktop app**: Easy desktop installation, with status bar icon, powered by [tauri](https://github.com/tauri-apps/tauri/).
- 📚  **Libraries**: [Javascript / Typescript](https://www.npmjs.com/package/@tomic/lib), [React](https://www.npmjs.com/package/@tomic/react), [Svelte](https://www.npmjs.com/package/@tomic/svelte)

Powered by Rust, [atomic-lib](https://crates.io/crates/atomic-lib) and [more](Cargo.toml).

https://user-images.githubusercontent.com/2183313/139728539-d69b899f-6f9b-44cb-a1b7-bbab68beac0c.mp4

## Table of contents

- [Table of contents](#table-of-contents)
- [When should you use this](#when-should-you-use-this)
- [When _not_ to use this](#when-not-to-use-this)
- [Installation \& getting started](#installation--getting-started)
  - [1. Run using docker](#1-run-using-docker)
  - [2. Install desktop build (macOS only)](#2-install-desktop-build-macos-only)
  - [3. Run pre-compiled binary](#3-run-pre-compiled-binary)
  - [4. Install using cargo](#4-install-using-cargo)
  - [5. Compile from source](#5-compile-from-source)
- [Initial setup and configuration](#initial-setup-and-configuration)
  - [Running using a tunneling service (easy mode)](#running-using-a-tunneling-service-easy-mode)
  - [HTTPS Setup on a VPS (static IP required)](#https-setup-on-a-vps-static-ip-required)
    - [HTTPS Setup using external HTTPS proxy](#https-setup-using-external-https-proxy)
  - [Using `systemd` to run Atomic-Server as a service](#using-systemd-to-run-atomic-server-as-a-service)
- [Usage](#usage)
  - [Using AtomicServer with the browser GUI](#using-atomicserver-with-the-browser-gui)
  - [Use `atomic-cli` as client](#use-atomic-cli-as-client)
  - [API](#api)
- [FAQ \& Troubleshooting](#faq--troubleshooting)
  - [Can / should I create backups?](#can--should-i-create-backups)
  - [I lost the key / secret to my Root Agent, and the `/setup` invite is no longer usable! What now?](#i-lost-the-key--secret-to-my-root-agent-and-the-setup-invite-is-no-longer-usable-what-now)
  - [How do I migrate my data to a new domain?](#how-do-i-migrate-my-data-to-a-new-domain)
  - [How do I reset my database?](#how-do-i-reset-my-database)
  - [How do I make my data private, yet available online?](#how-do-i-make-my-data-private-yet-available-online)
  - [Items are missing in my Collections / Search results](#items-are-missing-in-my-collections--search-results)
  - [I get a `failed to retrieve` error when opening](#i-get-a-failed-to-retrieve-error-when-opening)
  - [Can I embed AtomicServer in another application?](#can-i-embed-atomicserver-in-another-application)
- [I want to use my own authorization. How do I do that?](#i-want-to-use-my-own-authorization-how-do-i-do-that)
  - [Where is my data stored on my machine?](#where-is-my-data-stored-on-my-machine)
- [Also in this Repo](#also-in-this-repo)
  - [`atomic-cli`](#atomic-cli)
  - [`atomic-lib`](#atomic-lib)
- [Also check out](#also-check-out)
- [Contribute](#contribute)

## When should you use this

- You want a powerful, lightweight, fast and easy to use **CMS or database** with live updates, editors, modelling capabilities and an intuitive API
- You want to build a webapplication, and like working with using [React](https://github.com/atomicdata-dev/atomic-data-browser) or [Svelte](https://github.com/atomicdata-dev/atomic-svelte).
- You want to make (high-value) **datasets as easily accessible as possible**
- You want to specify and share a **common vocabulary** / ontology / schema for some specific domain or dataset. Example classes [here](https://atomicdata.dev/classes).
- You want to use and **share linked data**, but don't want to deal with most of [the complexities of RDF](https://docs.atomicdata.dev/interoperability/rdf.html), SPARQL, Triple Stores, Named Graphs and Blank Nodes.
- You are interested in **re-decentralizing the web** or want want to work with tech that improves data ownership and interoperability.

## When _not_ to use this

- High-throughput **numerical data / numerical analysis**. AtomicServer does not have aggregate queries.
- If you need **high stability**, look further (for now). This is beta sofware and can change.
- You're dealing with **very sensitive / private data**. The built-in authorization mechanisms are relatively new and not rigorously tested. The database itself is not encrypted.
- **Complex query requirements**. We have queries with filters and features for path traversal, but it may fall short. Check out NEO4j, Apache Jena or maybe TerminusDB.

## Installation & getting started

You can run AtomicServer in five ways:

1. Using docker (probably the quickest): `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
2. Install a desktop build (macOS only as of now)
3. From a published [binary](https://github.com/atomicdata-dev/atomic-server/releases)
4. Using [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) from crates.io: `cargo install atomic-server`
5. Manually from source

When you're running AtomicServer, go to [Initial setup and configuration](#Initial-setup-and-configuration).
If you want to run this locally as a developer / contributor, check out [the Contributors guide](CONTRIBUTE.md).

### 1. Run using docker

- Run: `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
The `dockerfile` is located in the project root, above this `server` folder.
- If you want to make changes (e.g. to the port), make sure to pass the relevant CLI options (e.g. `--port 9883`).
- If you want to update, run `docker pull joepmeneer/atomic-server` and docker should fetch the latest version.

### 2. Install desktop build (macOS only)

We automatically build `.dmg` installers for MacOS. You can download them from the [releases page](https://github.com/atomicdata-dev/atomic-server/releases).

### 3. Run pre-compiled binary

Get the binaries from the [releases page](https://github.com/atomicdata-dev/atomic-server/releases) and copy them to your `bin` folder.

### 4. Install using cargo

```sh
# Install from source using cargo, and add it to your path
# If things go wrong, check out `Troubleshooting compiling from source:` below
cargo install atomic-server --locked
# Check the available options and commands
atomic-server --help
# Run it!
atomic-server
```

### 5. Compile from source

```sh
git clone git@github.com:atomicdata-dev/atomic-server.git
cd atomic-server/server
cargo run
```

If things go wrong while compiling from source:

```sh
# If cc-linker, pkg-config or libssl-dev is not installed, make sure to install them
sudo apt-get install -y build-essential pkg-config libssl-dev --fix-missing
```

## Initial setup and configuration

- You can configure the server by passing arguments (see `atomic-server --help`), or by setting ENV variables.
- The server loads the `.env` from the current path by default. Create a `.env` file from the default template in your current directory with `atomic-server generate-dotenv`
- After running the server, check the logs and take note of the `Agent Subject` and `Private key`. You should use these in the [`atomic-cli`](https://crates.io/crates/atomic-cli) and [atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser) clients for authorization.
- A directory is made: `~/.config/atomic`, which stores your newly created Agent keys, the HTTPS certificates other configuration. Depending on your OS, the actual data is stored in different locations. See use the `show-config` command to find out where, if you need the files.
- Visit `http://localhost:9883/setup` to **register your first (admin) user**. You can use an existing Agent, or create a new one. Note that if you create a `localhost` agent, it cannot be used on the web (since, well, it's local).

### Running using a tunneling service (easy mode)

If you want to make your -server available on the web, but don't want (or cannot) deal with setting up port-forwarding and DNS, you can use a tunneling service.
It's the easiest way to get your server to run on the web, yet still have full control over your server.

- Create an account on some tunneling service, such as [tunnelto.dev](https://tunnelto.dev/) (which we will use here). Make sure to reserve a subdomain, you want it to remain stable.
- `tunnelto --port 9883 --subdomain joepio --key YOUR_API_KEY`
- `atomic-server --domain joepio.tunnelto.dev --custom-server-url 'https://joepio.tunnelto.dev' --initialize`

### HTTPS Setup on a VPS (static IP required)

You'll probably want to make your Atomic Data available through HTTPS on some server.
You can use the embedded HTTPS / TLS setup powered by [LetsEncrypt](https://letsencrypt.org/), [acme_lib](https://docs.rs/acme-lib/0.8.1/acme_lib/index.html) and [rustls](https://github.com/ctz/rustls).

You can do this by passing these flags:

Run the server: `atomic-server --https --email some@example.com --domain example.com`.

You can also set these things using a `.env` or by setting them some other way.

Make sure the server is accessible at `ATOMIC_DOMAIN` at port 80, because Let's Encrypt will send an HTTP request to this server's `/.well-known` directory to check the keys.
The default Ports are `9883` for HTTP, and `9884` for HTTPS.
If you're running the server publicly, set these to `80` and `433`: `atomic-server --https --port 80 --port-https 433`.
It will now initialize the certificate.
Read the logs, watch for errors.

HTTPS certificates are automatically renewed when the server is restarted, and the certs are 4 weeks or older.
They are stored in your `.config/atomic/` dir.

#### HTTPS Setup using external HTTPS proxy

Atomic-server has built-in HTTPS support using letsencrypt, but there are usecases for using external TLS source (e.g. Traeffik / Nginx / Ingress).

To do this, users need to set these ENVS:

```ini
ATOMIC_DOMAIN=example.com
# We'll use this regular HTTP port, not the HTTPS one
ATOMIC_PORT=80
# Disable built-in letsencrypt
ATOMIC_HTTPS=false
# Since Atomic-server is no longer aware of the existence of the external HTTPS service, we need to set the full URL here:
ATOMIC_SERVER_URL=https://example.com
```

### Using `systemd` to run Atomic-Server as a service

In Linux operating systems, you can use `systemd` to manage running processes.
You can configure it to restart automatically, and collect logs with `journalctl`.

Create a service:

```sh
nano /etc/systemd/system/atomic.service
```

Add this to its contents, make changes if needed:

```
[Unit]
Description=Atomic-Server
#After=network.targetdd
StartLimitIntervalSec=0[Service]

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=/root/atomic-server
WorkingDirectory=/root/
EnvironmentFil=/root/.env

[Install]
WantedBy=multi-user.target
```

```sh
# start / status / restart commands:
systemctl start atomic
systemctl status atomic
systemctl restart atomic
# show recent logs, follow them on screen
journalctl -u atomic.service --since "1 hour ago" -f
```
## Usage

There are three ways to interact with this server:

- **GUI**: Use the [`atomic-data-browser`](https://github.com/atomicdata-dev/atomic-data-browser) JS frontend by visiting `localhost:9883`.
- **API**: We have a subset of the [API documented using Swagger / OpenAPI](https://editor.swagger.io/?url=https://raw.githubusercontent.com/atomicdata-dev/atomic-server/master/server/openapi.yml). Check out [./_requests.http](./example_requests.http) for various HTTP requests to the server. Also, [read the Atomic Data Docs](https://docs.atomicdata.dev/). You can also try the [react boilerplate](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx:0-1223) to build your own front-end app using [@tomic/lib](https://www.npmjs.com/package/@tomic/lib) and [@tomic/react](https://www.npmjs.com/package/@tomic/react).
- **CLI**: The [`atomic-cli`](https://crates.io/crates/atomic-cli/0.24.2) terminal app

### Using AtomicServer with the browser GUI

Open your server in your browser.
By default, that's [`http://localhost:9883`](http://localhost:9883).
Fun fact: `&#9883;` is HTML entity code for the Atom icon: ⚛.

The first screen should show you your [_Drive_](https://atomicdata.dev/classes/Drive).
You can think of this as your root folder.
It is the resource hosted at the root URL, effectively being the home page of your server.

There's an instruction on the screen about the `/setup` page.
Click this, and you'll get a screen showing an [_Invite_](https://atomicdata.dev/classes/Invite).
Normally, you could `Accept as new user`, but since you're running on `localhost`, you won't be able to use the newly created Agent on non-local Atomic-Servers.
Therefore, it may be best to create an Agent on some _other_ running server, such as the [demo Invite on AtomicData.dev](https://atomicdata.dev/invites/1).
And after that, copy the Secret from the `User settings` panel from AtomicData.dev, go back to your `localhost` version, and press `sign in`.
Paste the Secret, and voila! You're signed in.

Now, again go to `/setup`. This time, you can `Accept as {user}`.
After clicking, your Agent has gotten `write` rights for the Drive!
You can verify this by hovering over the description field, clicking the edit icon, and making a few changes.
You can also press the menu button (three dots, top left) and press `Data view` to see your agent after the `write` field.
Note that you can now edit every field.
You can also fetch your data now as various formats.

Try checking out the other features in the menu bar, and check out the `collections`.

### Use `atomic-cli` as client

`atomic-cli` is a useful terminal tool for interacting with `atomic-server`.
It makes it easy to query and edit Atomic Data from the command line.
[Check it out](https://github.com/atomicdata-dev/atomic-server/tree/master/cli).

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
We have a subset of the [API documented using Swagger / OpenAPI](https://editor.swagger.io/?url=https://raw.githubusercontent.com/atomicdata-dev/atomic-server/master/server/openapi.yml).
Also, read the [Atomic Data Docs](https://docs.atomicdata.dev/) to learn more about Collections, Commits, JSON-AD and other concepts used here.

## FAQ & Troubleshooting

### Can / should I create backups?

You should.
Run `atomic-server export` to create a JSON-AD backup in your `~/.config/atomic/backups` folder.
Import them using `atomic-server import -p ~/.config/atomic/backups/${date}.json`.'
You could also copy all folders `atomic-server` uses. To see what these are, see `atomic-server show-config`.

### I lost the key / secret to my Root Agent, and the `/setup` invite is no longer usable! What now?

You can run `atomic-server --initialize` to recreate the `/setup` invite. It will be reset to `1` usage.

### How do I migrate my data to a new domain?

There are no helper functions for this, but you could `atomic-server export` your JSON-AD, and find + replace your old domain with the new one.
This could especially be helpful if you're running at `localhost:9883` and want to move to a live server.

### How do I reset my database?

`atomic-server reset`

### How do I make my data private, yet available online?

You can press the menu icon (the three dots in the navigation bar), go to sharing, and uncheck the public `read` right.
See the [Hierarchy chapter](https://docs.atomicdata.dev/hierarchy.html) in the docs on more info of the authorization model.

### Items are missing in my Collections / Search results

You might have a problem with your indexes.
Try rebuilding the indexes using `atomic-server --rebuild-index`.
Also, if you can, recreate and describe the indexing issue in the issue tracker, so we can fix it.

### I get a `failed to retrieve` error when opening

Try re-initializing atomic server `atomic-server --initialize`.

### Can I embed AtomicServer in another application?

Yes. This is what I'm doing with the Tauri desktop distribution of AtomicServer.
Check out the [`desktop`](https://github.com/atomicdata-dev/atomic-server/tree/master/desktop) code for an example!

## I want to use my own authorization. How do I do that?

You can disable all authorization using `--public-mode`.
Make sure AtomicServer is not publicly accessible, because this will allow anyone to read any data.

### Where is my data stored on my machine?

It depends on your operating system, because some data is _temporary_, others are _configuration files_, and so forth. Run `atomic-server show-config` to see the used paths. You can overwrite these if you want, see `--help`.

https://user-images.githubusercontent.com/2183313/139728539-d69b899f-6f9b-44cb-a1b7-bbab68beac0c.mp4

## Also in this Repo
### [`atomic-cli`](cli/README.md)

[![crates.io](https://img.shields.io/crates/v/atomic-cli)](https://crates.io/crates/atomic-cli)

A simple Command Line Interface tool to fetch, create and query Atomic Data.
Especially useful for interacting with an AtomicServer.

[→ Read more](cli/README.md)

### [`atomic-lib`](lib/README)

[![crates.io](https://img.shields.io/crates/v/atomic_lib)](https://crates.io/crates/atomic_lib)
[![Released API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)

A Rust library to serialize, parse, store, convert, validate, edit, fetch and store Atomic Data.
Powers both `atomic-cli` and `atomic-server`.

[→ Read more](lib/README.md)

## Also check out

- [Atomic-Data-Browser](https://github.com/atomicdata-dev/atomic-data-browser), an in-browser app for viewing and editing atomic data. Also contains a typescript / react front-end library. Will replace most of the html templating in this project.
- [The Docs](https://github.com/ontola/atomic-data-docs), a book containing detailed documentation of Atomic Data.
- [RayCast extension](https://www.raycast.com/atomicdata-dev/atomic-data-browser) for searching stuff
- [Newsletter](http://eepurl.com/hHcRA1)
- [Discord][discord-url]

## Contribute

Issues and PR's are welcome!
And join our [Discord][discord-url]!
[Read more in the Contributors guide.](CONTRIBUTE.md)

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
