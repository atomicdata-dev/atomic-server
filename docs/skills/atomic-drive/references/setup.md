# Install and configure the Atomic drive skill

Share this **whole skill folder**. It contains instructions and source helpers,
not your connection configuration, agent credential, private drive contents or
compiled Keychain binary. Each colleague configures their own endpoint and
identity, granted access to the drives they need. It runs on the machine where
the agent's command tool executes; `localhost` means that machine.

Copy the folder into a skill directory supported by your agent. For Codex, a
repo's `.agents/skills/atomic-drive/` is suitable for team use. Keep machine
configuration outside the repository. See [official skills documentation](https://developers.openai.com/blog/skills-agents-sdk).

## Runtime compatibility

This bootstrap is extracted from a working HTTP skill. It requires an Atomic
JavaScript build exporting `Agent`, `Store`, `enableLoro`,
`readResourceCompact`, `createResourceFromCompact` and `setResourceProperty`,
plus the document text/body adapters. The tested source revision is
[`0f9b5f4298e41a2da7360c847f455b724b7518ed`](https://github.com/ontola/atomic-server/tree/0f9b5f4298e41a2da7360c847f455b724b7518ed)
from the MCP work. Those compact-resource helpers and the `browser/mcp` package
are not in `develop` at this documentation PR's base. Do not assume an npm
package or ordinary develop build supplies them. This docs bundle does not
add the missing runtime code or start an MCP server.

With Node 22 and pnpm 10, build that revision in a separate checkout:

```sh
git clone https://github.com/ontola/atomic-server.git atomic-drive-runtime
cd atomic-drive-runtime
git checkout 0f9b5f4298e41a2da7360c847f455b724b7518ed
cd browser
pnpm install --frozen-lockfile
pnpm --filter @tomic/lib build
pnpm --filter @tomic/mcp build
```

No Rust build, frontend deployment or MCP process is required for these helper
modules. The installed AtomicServer must support the same signed HTTP and
Loro document protocol. A built revision can be retained independently of the
agent workspace. The helper checks the required library exports before reading
a credential. Incompatible runtime errors should be resolved by selecting a
compatible build, not by disabling checks.

## Public configuration

Create `~/.config/atomic-drive/bootstrap.json`, or set `ATOMIC_BOOTSTRAP_CONFIG`
to another JSON file. Fill in your own public IDs and local paths:

```json
{
  "serverUrl": "http://localhost:9883",
  "agent": "atomic:agent:YOUR_PUBLIC_AGENT_ID",
  "drive": "atomic:YOUR_DRIVE_ID",
  "library": "/absolute/path/atomic-drive-runtime/browser/lib/dist/index.js",
  "documentReader": "/absolute/path/atomic-drive-runtime/browser/mcp/bin/document-text.js",
  "documentWriter": "/absolute/path/atomic-drive-runtime/browser/mcp/bin/document-body.js",
  "credentialCommand": {
    "command": "/absolute/path/atomic-drive/scripts/keychain",
    "args": ["get"]
  }
}
```

Module paths may also be relative to the configuration file. Use actual paths,
not a literal `~`. `serverUrl` is an origin: loopback HTTP or remote HTTPS, with
no username, password, path, query or fragment. To use another port, change the
URL or override it per invocation:

```sh
ATOMIC_SERVER_URL=http://localhost:11870 node scripts/atomic.mjs identity
ATOMIC_SERVER_URL=https://atomic.example.org node scripts/atomic.mjs identity
```

`identity` prints public metadata only. `read <subject>` can access authorized
subjects outside the configured drive; `search` and registry loading are scoped
to that drive. No secret belongs in this configuration.

## Credential sources

Prefer a trusted local credential command. It receives its configured string
arguments followed by the **public agent ID**, and writes the agent secret to
stdout. It must not echo the secret into logs. The helper captures the output
internally, passes it to `Agent.fromSecret`, verifies the resulting public
identity, and never prints command output or stderr. There is no shell expansion.
An executable can wrap your operating system's credential store. Arguments are
configuration, not a place for the secret.

On macOS, the included source uses Keychain service `io.atomic.codex-bootstrap`:

```sh
cc scripts/keychain.c -framework Security -framework CoreFoundation -o scripts/keychain
```

Provision it interactively, outside an agent/tool transcript. For example, in
Bash, substituting your public agent ID:

```sh
read -r -s -p 'Atomic agent secret: ' atomic_drive_input
printf '%s' "$atomic_drive_input" | scripts/keychain put atomic:agent:YOUR_PUBLIC_AGENT_ID
unset atomic_drive_input
```

Only the operator should run this provisioning step. The shared instructions
never ask an agent to retrieve or display a secret. Obtain an identity through
your existing Atomic setup and arrange its permissions; this skill does not
provision accounts or grant itself access.

For an environment managed by a secret injector, replace `credentialCommand`
with `"credentialEnv": "ATOMIC_AGENT_SECRET"`. Supply the value through that
injector, not a shell command written into a chat or `.env` committed to Git.
Select exactly one source. The legacy `keychainHelper` path is also understood
for compatibility. Registry script execution is unavailable in environment mode:
the helper does not forward secret variables to fetched code.

## Optional drive-backed skills

Ordinary read/search/edit use needs no skill registry. To enable `catalog` and
`load`, add a public `registry` subject to the configuration. It must name a
document in the configured drive containing JSON of this shape:

```json
{
  "version": 1,
  "skills": [
    {
      "name": "team-workspace",
      "description": "Team workspace instructions and reference routing",
      "subject": "atomic:YOUR_INSTRUCTION_DOCUMENT_ID",
      "enabled": true,
      "scripts": [
        {
          "path": "summarize.mjs",
          "subject": "atomic:YOUR_SCRIPT_DOCUMENT_ID",
          "enabled": false,
          "sha256": "REPLACE_WITH_SHA256_OF_EXACT_SCRIPT_BYTES"
        }
      ]
    }
  ]
}
```

Omit `scripts` when unused. A script document contains exactly one fenced
JavaScript block; its pin covers the block contents plus the trailing newline.
Only explicitly enabled scripts run, after pin verification. Registry and
instruction documents must belong to the configured drive. The operator creates
and reviews this registry; installing the skill does not create one.

## Validate

From the skill directory:

```sh
node --test scripts/atomic.test.mjs
node scripts/atomic.mjs help
node scripts/atomic.mjs identity
node scripts/atomic.mjs read atomic:YOUR_RESOURCE_ID
```

Tests cover configuration, endpoint rejection, credential handling and bootstrap
behavior with synthetic adapters. A read-only compatibility smoke check was also
performed against the existing local HTTP replica using its preinstalled runtime.
No remote HTTPS server, new account, Linux credential-store adapter or
production write is certified. All reads and writes use HTTP, even though the
text adapters are compiled from the MCP package. The command client has no local
database and disconnects when each invocation completes.
