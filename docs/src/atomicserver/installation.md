{{#title Installing AtomicServer}}
# Setup / installation

You can run AtomicServer in different ways:

1. Using docker (probably the quickest): `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
2. From a published [binary](https://github.com/atomicdata-dev/atomic-server/releases)
3. Using [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) from crates.io: `cargo install atomic-server`
4. Manually from source

If you want to run AtomicServer locally as a developer / contributor, check out [the Contributors guide](https://github.com/atomicdata-dev/atomic-server/blob/develop/CONTRIBUTING.md).

## 1. Run using docker

- Run: `docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
The `dockerfile` is located in the project root, above this `server` folder.
- See dockerhub for a [list of all the available tags](https://hub.docker.com/repository/docker/joepmeneer/atomic-server/tags?page=1&ordering=last_updated) (e.g. the `develop` tag for the very latest version)
- If you want to make changes (e.g. to the port), make sure to pass the relevant CLI options (e.g. `--port 9883`).
- If you want to update, run `docker pull joepmeneer/atomic-server` and docker should fetch the latest version.
- By default, docker downloads the `latest` tag. You can find other tags [here](https://hub.docker.com/repository/docker/joepmeneer/atomic-server/tags).

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
# Since Atomic-server is no longer aware of the existence of the external HTTPS service, we need to set the full URL here:
ATOMIC_SERVER_URL=https://example.com
```

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

# Install Atomic Data Server with docker-compose and cloudflare tunnel

To install atomic server with docker-compose and cloudflared tunnel, create docker-compose.yml

```yaml
version: "3.4"

services:
  atomic-server:
    image: joepmeneer/atomic-server
    container_name: atomic-server
    restart: unless-stopped
    environment:
      ATOMIC_DOMAIN: ${ATOMIC_DOMAIN}
      ATOMIC_SERVER_URL: ${ATOMIC_SERVER_URL}
    ports:
      - 8080:80
    volumes:
      - data:/atomic-storage
  cloudflared:
    image: cloudflare/cloudflared:latest
    environment:
      TUNNEL_URL: ${TUNNEL_URL}
      TUNNEL_TOKEN: ${TUNNEL_TOKEN}
    command: "tunnel run"
    volumes:
      - ./cloudflared:/etc/cloudflared
    links:
      - atomic-server
    depends_on:
      - atomic-server
volumes:
  data:
```

and .env file with:

```
TUNNEL_URL=http://atomic-server:8080
TUNNEL_TOKEN=op://at.terraphim.dev/token
ATOMIC_SERVER_URL=op://Shared/at.terraphim.dev/server_url
ATOMIC_DOMAIN=op://Shared/at.terraphim.dev/domain
```

to use with one password cli `op run --no-masking --env-file .env -- docker-compose up`

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
          Recreates the `/setup` Invite for creating a new Root User. Also re-runs various populate commands, and re-builds the index

          [env: ATOMIC_INITIALIZE=]

      --rebuild-indexes
          Re-builds the indexes. Parses all the resources. Do this when updating requires it, or if you have issues with Collections / Queries / Search

          [env: ATOMIC_REBUILD_INDEX=]

      --development
          Use staging environments for services like LetsEncrypt

          [env: ATOMIC_DEVELOPMENT=]

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

  -h, --help
          Print help information (use `-h` for a summary)

  -V, --version
          Print version information
```
