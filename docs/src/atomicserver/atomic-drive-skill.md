# Atomic drive skill for coding agents

The repository includes a shareable [Atomic drive skill](https://github.com/ontola/atomic-server/tree/develop/docs/skills/atomic-drive)
for agents that can run local commands. It reads and edits Atomic resources over
signed HTTP using a locally configured JavaScript runtime and agent credential.
It can also discover explicitly enabled skills stored as Atomic documents.

The server origin and port, public agent and drive IDs, runtime paths, and
credential source are configured per machine. The helper supports loopback HTTP
and remote HTTPS. Each colleague uses their own identity and granted access;
sharing the skill does not share an account, private data or credential.

Install the entire folder into your agent's skill directory and follow its
[setup and compatibility instructions](https://github.com/ontola/atomic-server/blob/develop/docs/skills/atomic-drive/references/setup.md).
The current bundle requires compact-resource and document utilities from the
linked MCP work revision, which are not in this documentation change's develop
base. It is an HTTP bootstrap example, not a claim that every published SDK or
server release supports those utilities.

The assistant invokes a local Node helper, which calls AtomicServer through
`@tomic/lib`. This does not require an MCP server or WebSocket subscription.
The AtomicServer holds durable state. Writes create ordinary signed commits,
require the user's task authorization and server permissions, and must be
acknowledged. Failed creations should be inspected by their reported subject
before retrying; this short-lived client has no persistent outbox.
