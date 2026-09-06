{{#title Installing AtomicServer}}

# Setup / installation

You can run AtomicServer in different ways:

1. Using docker (probably the quickest): `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage ghcr.io/ontola/atomic-server`
2. From a published [binary](https://github.com/atomicdata-dev/atomic-server/releases)
3. Using [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) from crates.io: `cargo install atomic-server`
4. Manually from source

If you want to run AtomicServer locally as a developer / contributor, check out [the Contributors guide](https://github.com/atomicdata-dev/atomic-server/blob/develop/CONTRIBUTING.md).

## Privacy: your server never phones home

A self-hosted AtomicServer talks to nobody but you. There is no telemetry, no
analytics, and no background reporting in the open-source build. It never
contacts any control plane, and it does not know that a hosted service
(AtomicCloud) exists — `GET /node-info` reports `managed: false` and no portal.

The optional hosted-sync integration (heartbeat, per-drive quotas, enrollment
reporting) is **opt-in and lives outside the open core**: it only runs in the
separate closed managed-node wrapper, and only when that wrapper is explicitly
configured with a control-plane URL. A stock `atomic-server` binary has none of
that code compiled into a code path that runs by default — it installs an open
sync policy (every drive allowed, no quotas) and passes a no-op readiness hook.
So running your own node keeps your data, and your traffic, entirely yours.

The only exception is [error reporting](#error-reporting-opt-in), which is off
unless you configure it yourself.

## Error reporting (opt-in)

AtomicServer can report crashes and `error`-level log events to a
[Sentry](https://sentry.io) project (or a self-hosted Sentry). This is off by
default: without a DSN no Sentry client is created and nothing leaves the
machine. To enable it, set:

```sh
# Server-side: panics and error logs, with the HTTP request that caused them.
SENTRY_DSN=https://<key>@<host>/<project>
# Front-end: hands the bundled data-browser its own (public) DSN at runtime,
# so browser errors are reported too. Separate, because browser DSNs are public.
SENTRY_DSN_BROWSER=https://<key>@<host>/<project>
# Tag events with where they came from (optional).
SENTRY_ENVIRONMENT=production
```

Only errors are sent. Performance tracing stays off (use `ATOMIC_TRACING=opentelemetry`
for that), no personal data is attached, and the served front-end bundle is
identical whether or not a DSN is set: it only contacts Sentry when the server
injects one.

## 1. Run using docker

- Run: `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage ghcr.io/ontola/atomic-server`
The `dockerfile` is located in the project root, above this `server` folder.
- Images are published to the GitHub Container Registry — see the [list of all the available tags](https://github.com/ontola/atomic-server/pkgs/container/atomic-server) (e.g. the `develop` tag for the very latest version)
- If you want to make changes (e.g. to the port), make sure to pass the relevant CLI options (e.g. `--port 9883`).
- If you want to update, run `docker pull ghcr.io/ontola/atomic-server` and docker should fetch the latest version.
- By default, docker downloads the `latest` tag. You can find other tags [here](https://github.com/ontola/atomic-server/pkgs/container/atomic-server).

## 2. Run pre-compiled binary

Get the binaries from the [releases page](https://github.com/atomicdata-dev/atomic-server/releases) and copy them to your `bin` folder.

## 3. Install using cargo

```sh
# Install from source using cargo, and add it to your path
# If things go wrong, check out `Troubleshooting compiling from source:` below
cargo install atomic-server --locked
# Check the available options and commands
atomic-server --help
# Run it!
atomic-server
```

## 4. Compile from source

```sh
# make sure pnpm is installed and available in path! https://pnpm.io/
pnpm --version
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
- Visit `http://localhost:9883/setup` to **register your first (admin) user**. You can use an existing Agent, or create a new one. Note that if you create a `localhost` agent, it cannot be used on the web (since, well, it's local). More info and steps in [getting started with the GUI](gui.md).

## Serving one Drive as your front page (opt-in)

By default, opening `/` sends visitors who aren't signed in to the welcome /
sign-in screen. That is the right default for a server hosting several Drives,
or one whose root isn't meant to be public — it doesn't assume the root is a
Drive that everybody may read.

If your server hosts a single site, wiki or dataset that the public should just
*see*, point `ATOMIC_HOME_DRIVE` at that Drive:

```env
# The Drive at the server root
ATOMIC_HOME_DRIVE=internal:/

# ...or a specific Drive
# ATOMIC_HOME_DRIVE=did:ad:drive:hqfpna7s5ke
```

Visiting `/` then opens that Drive directly, for signed-out visitors too.
Signed-in users still reach their own Drives from the sidebar.

Three things worth knowing:

- **Make the Drive readable by the public Agent.** Otherwise signed-out
  visitors get an authorization error instead of your front page. Open the
  Drive, use `share` in the context menu, and give `public` read access.
- **It costs nothing at runtime.** The subject is written into the HTML the
  server already serves, so the browser routes to it on the first render —
  no extra request, and no wait.
- **`internal:` subjects are resolved for you.** The server rewrites
  `internal:/` to its own absolute URL before handing it to the browser,
  because a browser has no host to fetch a bare `internal:` subject from. You
  can configure whichever form you have; both end up working.

You can read the current setting back from the `/server` endpoint, under
`https://atomicdata.dev/properties/server/homeDrive`.

## Vector search embeddings (opt-in)

Semantic search is opt-in twice over: it has to be **compiled in**, and then **switched on**.

The official release binaries and the default `cargo install atomic-server` build do **not** include it, because the embedding stack (fastembed, lancedb, arrow, ort) is a very large dependency for something most deployments never turn on. To get it, build from source with the feature enabled:

```sh
cargo install atomic-server --features vector-search
```

That build needs `protoc` (`protobuf-compiler`) available. It does not currently work for musl targets, where `ort` has no prebuilt ONNX Runtime binary.

With such a build, pass **`--enable-vector-index`** (or set **`ATOMIC_ENABLE_VECTOR_INDEX`**) to turn it on, since loading embedding models and indexing every write has a real performance cost. Passing the flag to a build that lacks the feature logs a warning and does nothing. Once enabled, the server runs [fastembed](https://github.com/Anush008/fastembed-rs) locally by default. To use [OpenRouter](https://openrouter.ai/) embeddings instead, pass **`--openrouter-api-key`** and **`--openrouter-embedding-model`** (or set **`OPENROUTER_API_KEY`** and **`OPENROUTER_EMBEDDING_MODEL`** in your environment or `.env`). **`--openrouter-embedding-dimensions`** / **`OPENROUTER_EMBEDDING_DIMENSIONS`** is optional (some models ignore it). **`--gpu-indexing`** / **`ATOMIC_GPU_INDEXING`** uses GPU acceleration for the default local embedding and reranker, not for OpenRouter.

## Running using a tunneling service (easy mode)

If you want to make your -server available on the web, but don't want (or cannot) deal with setting up port-forwarding and DNS, you can use a tunneling service.
It's the easiest way to get your server to run on the web, yet still have full control over your server.

- Create an account on some tunneling service, such as [tunnelto.dev](https://tunnelto.dev/) (which we will use here). Make sure to reserve a subdomain, you want it to remain stable.
- `tunnelto --port 9883 --subdomain joepio --key YOUR_API_KEY`
- `atomic-server --domain joepio.tunnelto.dev --custom-server-url 'https://joepio.tunnelto.dev' --initialize`

## HTTPS Setup on a VPS (static IP required)

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

## HTTPS Setup using external HTTPS proxy

Atomic-server has built-in HTTPS support using letsencrypt, but there are usecases for using external TLS source (e.g. Traeffik / Nginx / Ingress).

To do this, users need to set these ENVS:

```ini
ATOMIC_DOMAIN=example.com
# We'll use this regular HTTP port, not the HTTPS one
ATOMIC_PORT=80
# Disable built-in letsencrypt
ATOMIC_HTTPS=false
```

`ATOMIC_DOMAIN` is what the server uses to build its own links, so set it to the
name your users type — not to `localhost`, even though that is where the proxy
forwards to. Getting this wrong mostly shows up as links pointing at the wrong
host.

Behind a proxy the server cannot tell that it is reachable from the internet:
the connection arrives from the proxy, on the local interface. It will not warn
you. See [Putting your server on the internet](#putting-your-server-on-the-internet)
for what to set so strangers cannot store their data on your disk.

## Putting your server on the internet

By default, **anyone who can reach your server can create an account on it and
store their data on your disk.** That is the right behaviour on your laptop or a
home network. On a public address it makes your server an open sign-up form for
free storage.

This is not about privacy of what you already have — your existing Drives stay
as private as their permissions say. It is about who may put *new* data here.

### Name yourself as the owner

You need your Agent ID: a public identifier that looks like
`did:ad:agent:AbCd...`. If you do not have one yet, run the server on your own
machine first, click **Create account**, and copy the Agent ID from Settings.
Your phone or the desktop app work equally well — an identity is a keypair, it
does not belong to any particular server.

Then set it on the server that will be public:

```ini
ATOMIC_OWNER_AGENT=did:ad:agent:AbCd...
```

That is the whole setup. Restart, and the server will say so at boot:

```text
Only its owner can create new Drives here (did:ad:agent:AbCd...).
```

> **Use the Agent ID, never the secret.** The ID is public and safe to put in a
> config file. The secret is your private key; the server never needs it and
> refuses to start if you paste one here.

### What changes, and what does not

| Still works | Now refused |
| --- | --- |
| Anyone reading a Drive you made public | A stranger creating an account here |
| People you invited, in the Drives you invited them to | A stranger pushing a new Drive over sync |
| Your own other devices, signing in as you | A stranger uploading files to a Drive they invented |
| Every Drive already on this server, including guests' | |

Drives that already exist keep working. Turning this on never revokes access to
data that is already on the disk — including Drives created before you set it,
or by people you invited.

New Drives you create are enrolled automatically, because you are the owner. Your
second device is the same Agent, so it needs nothing extra.

### If you are behind a reverse proxy or a tunnel

**The server cannot detect this, and will not warn you.** With nginx, Caddy,
Traefik, Docker port mapping, a Cloudflare Tunnel, or Tailscale in front, every
request arrives from the proxy on a local address, and `ATOMIC_DOMAIN` is often
still `localhost`. As far as the process can tell, it is a private machine.

If your server is reachable from the internet by any route, set
`ATOMIC_OWNER_AGENT`. Nothing else infers it for you.

### Running an open server on purpose

If you *want* a server other people can sign up on — a shared instance for a
team or a community — that is still supported, and is what you get by default.
To keep it open and silence the boot warning, say so:

```ini
ATOMIC_HOST_MODE=open
```

Do this deliberately. It means anyone who can reach the address can store data
on your disk, and there is currently no quota.

### Troubleshooting

**"ATOMIC_HOST_MODE=owner needs ATOMIC_OWNER_AGENT to be set"** — you asked for a
gated server without saying whose it is. Set `ATOMIC_OWNER_AGENT`, or use
`ATOMIC_HOST_MODE=open` if you meant to run an open one. The server refuses to
start rather than falling back to open, because a typo in a config file should
not quietly publish your disk.

**"ATOMIC_OWNER_AGENT looks like an Agent *secret*"** — you pasted the private
key. Open the secret and use the `subject` field inside it, or copy the Agent ID
from Settings.

**"This server does not host new Drives"** — someone (possibly you, in another
browser) tried to create an account. Sign in with the owner's secret instead. If
you meant to let this person in, invite them to a specific Drive rather than
giving them one of their own.

**I locked myself out.** You did not: `ATOMIC_OWNER_AGENT` is read fresh at every
boot and is never stored. Change it and restart, or remove it to go back to an
open server.

## Using `systemd` to run Atomic-Server as a service

In Linux operating systems, you can use `systemd` to manage running processes.
You can configure it to restart automatically, and collect logs with `journalctl`.

Create a service:

```sh
nano /etc/systemd/system/atomic.service
```

Add this to its contents, make changes if needed:

```service
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

## AtomicServer CLI options / ENV vars

(run `atomic-server --help` to see the latest options)

```
Create, share and model Atomic Data with this graph database server. Run atomic-server without any arguments to start the server. Use --help to learn about the options.

Usage: atomic-server [OPTIONS] [COMMAND]

Commands:
  export
          Create and save a JSON-AD backup of the store
  import
          Import a JSON-AD file or stream to the store. By default creates Commits for all changes, maintaining version history. Use --force to allow importing other types of files
  generate-dotenv
          Creates a `.env` file in your current directory that shows various options that you can set
  show-config
          Returns the currently selected options, based on the passed flags and parsed environment variables
  reset
          Danger! Removes all data from the store
  help
          Print this message or the help of the given subcommand(s)

Options:
      --initialize
          Recreates the initial Invite for creating a new Root User, prints it to console. Also re-runs various populate commands, and re-builds the index

          [env: ATOMIC_INITIALIZE=]

      --rebuild-indexes <INDEX_TYPE>
          Re-builds the indexes. Parses all the resources. Do this when updating requires it, or if you have issues with Collections / Queries / Search
          [possible values: all, atoms, vector, search]

          [env: ATOMIC_REBUILD_INDEX=]

      --development
          Use staging environments for services like LetsEncrypt

          [env: ATOMIC_DEVELOPMENT=]

      --envelope-retention <ENVELOPE_RETENTION>
          Which signed commit envelopes this node keeps per resource: `latest` (the envelope that produced the current state; the default) or `all` (every envelope, so History shows a verified signer per change)

          [env: ATOMIC_ENVELOPE_RETENTION=]
          [default: latest]

      --domain <DOMAIN>
          The origin domain where the app is hosted, without the port and schema values

          [env: ATOMIC_DOMAIN=]
          [default: localhost]

  -p, --port <PORT>
          The port where the HTTP app is available. Set to 80 if you want this to be available on the network

          [env: ATOMIC_PORT=]
          [default: 9883]

      --port-https <PORT_HTTPS>
          The port where the HTTPS app is available. Set to 443 if you want this to be available on the network

          [env: ATOMIC_PORT_HTTPS=]
          [default: 9884]

      --ip <IP>
          The IP address of the server. Set to :: if you want this to be available to other devices on your network

          [env: ATOMIC_IP=]
          [default: ::]

      --https
          Use HTTPS instead of HTTP. Will get certificates from LetsEncrypt fully automated

          [env: ATOMIC_HTTPS=]

      --https-dns
          Initializes DNS-01 challenge for LetsEncrypt. Use this if you want to use subdomains

          [env: ATOMIC_HTTPS_DNS=]

      --email <EMAIL>
          The contact mail address for Let's Encrypt HTTPS setup

          [env: ATOMIC_EMAIL=]

      --script <SCRIPT>
          Custom JS script to include in the body of the HTML template

          [env: ATOMIC_SCRIPT=]
          [default: ]

      --config-dir <CONFIG_DIR>
          Path for atomic data config directory. Defaults to "~/.config/atomic/""

          [env: ATOMIC_CONFIG_DIR=]

      --data-dir <DATA_DIR>
          Path for atomic data store folder. Contains your Store, uploaded files and more. Default value depends on your OS

          [env: ATOMIC_DATA_DIR=]

      --cache-dir <CACHE_DIR>
          Path for the atomic data cache folder. Contains search index, temp files and more. Default value depends on your OS

          [env: ATOMIC_CACHE_DIR=]

      --public-mode
          CAUTION: Skip authentication checks, making all data publicly readable. Improves performance

          [env: ATOMIC_PUBLIC_MODE=]

      --server-url <SERVER_URL>
          The full URL of the server. It should resolve to the home page. Set this if you use an external server or tunnel, instead of directly exposing atomic-server. If you leave this out, it will be generated from `domain`, `port` and `http` / `https`

          [env: ATOMIC_SERVER_URL=]

      --log-level <LOG_LEVEL>
          How much logs you want. Also influences what is sent to your trace service, if you've set one (e.g. OpenTelemetry)

          [env: RUST_LOG=trace]
          [default: info]
          [possible values: warn, info, debug, trace]

      --trace <TRACE>
          How you want to trace what's going on with the server. Useful for monitoring performance and errors in production. Combine with `log_level` to get more or less data (`trace` is the most verbose)

          [env: ATOMIC_TRACING=opentelemetry]
          [default: stdout]

          Possible values:
          - stdout:
            Log to STDOUT in your terminal
          - chrome:
            Create a file in the current directory with tracing data, that can be opened with the chrome://tracing/ URL
          - opentelemetry:
            Log to a local OpenTelemetry service (e.g. Jaeger), using default ports

      --slow-mode
          Introduces random delays in the server, to simulate a slow connection. Useful for testing

          [env: ATOMIC_SLOW_MODE=]

      --clear-remote-cache
          Removes all remote resources from the store

          [env: ATOMIC_CLEAR_REMOTE_CACHE=]

      --gpu-indexing
          Use the GPU (if available) for processing vector search embeddings

          [env: ATOMIC_GPU_INDEXING=]

      --enable-vector-index
          Opt in to vector embedding models and Lance index builds for semantic search. Off by default: loading embedding models and indexing every write has a real performance cost, so it should be a deliberate choice rather than the default.

          [env: ATOMIC_ENABLE_VECTOR_INDEX=]

      --skip-vector-index
          Deprecated: vector indexing is now off by default. Kept only so existing scripts/deployments that pass this flag keep working; it is a no-op unless combined with `--enable-vector-index`, in which case it forces indexing off again.

          [env: ATOMIC_SKIP_VECTOR_INDEX=]

      --openrouter-api-key <OPENROUTER_API_KEY>
          OpenRouter API key for remote embeddings instead of local fastembed

          [env: OPENROUTER_API_KEY=]

      --openrouter-embedding-model <OPENROUTER_EMBEDDING_MODEL>
          OpenRouter embedding model id (required when `OPENROUTER_API_KEY` is set)

          [env: OPENROUTER_EMBEDDING_MODEL=]

      --openrouter-embedding-dimensions <OPENROUTER_EMBEDDING_DIMENSIONS>
          Optional embedding vector dimensions for OpenRouter (JSON `dimensions` field; not all models honor it). Empty string is treated as unset.

          [env: OPENROUTER_EMBEDDING_DIMENSIONS=]

  -h, --help
          Print help information (use `-h` for a summary)

  -V, --version
          Print version information
```
