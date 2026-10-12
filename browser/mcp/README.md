# @tomic/mcp

An [MCP](https://modelcontextprotocol.io) server that lets an LLM client
(Claude Code, Claude Desktop, Cursor, ...) read and edit your Atomic Data.

It is a small bridge to the `/mcp` endpoint of your own AtomicServer, which is
the one implementation of the tools (the same endpoint claude.ai connects to).
You connect once: you pick in the app what the connection may reach and whether
it may edit, and you can revoke it at any time. Your own secret is never
involved, and every edit is a signed commit by an identity of its own that is
shown under **Connected apps**, so you can see what it did.

## Setup

1. Connect this machine. It prints a link and opens it in your browser; pick
   the drives to share, choose read only or read and edit, and click
   **Allow**.

   ```sh
   ATOMIC_SERVER_URL=https://atomicdata.dev npx -y @tomic/mcp connect
   ```

2. Add it to your client.

   Claude Code:

   ```sh
   claude mcp add atomic -e ATOMIC_SERVER_URL=https://atomicdata.dev -- npx -y @tomic/mcp
   ```

   Claude Desktop, Cursor and others (`mcpServers` in their config file):

   ```json
   {
     "mcpServers": {
       "atomic": {
         "command": "npx",
         "args": ["-y", "@tomic/mcp"],
         "env": { "ATOMIC_SERVER_URL": "https://atomicdata.dev" }
       }
     }
   }
   ```

If you skip step 1, the tools answer with the command to run instead, so the
assistant can hand it to you.

To see or revoke what you connected, open your account settings in the app
(`/app/agent`), under **Connected apps**. Revoking takes the connection off
every drive it could reach.

The token is stored in `~/.config/atomic-mcp/<server>.json` (or under
`$XDG_CONFIG_HOME`), readable by you only. Delete that file to disconnect this
machine without the app; revoke it in the app to cut it off on the server.

A client that cannot run a local process (claude.ai) connects to
`https://<your server>/mcp` directly and signs in through the same approval
page.

### With the desktop app

The approval page needs your identity, which the AtomicServer desktop app
holds and a browser on the same machine may not. Run
`ATOMIC_SERVER_URL=http://localhost:9883 npx -y @tomic/mcp connect --desktop`
and the approval page opens in the desktop app instead of the browser.

### Environment variables

| Variable             | Required | Meaning                                                                                       |
| -------------------- | -------- | --------------------------------------------------------------------------------------------- |
| `ATOMIC_SERVER_URL`  | yes      | The server your drives live on.                                                               |
| `ATOMIC_CLIENT_NAME` | no       | The name you see in the app. Defaults to `AI assistant on <hostname>`.                        |
| `ATOMIC_READ_ONLY`   | no       | `true` on `connect` asks for read only. You can still change it on the approval page.         |

## Tools

The node decides the list; a connection that may not edit sees only the read
tools.

| Tool               | What it does                                                             |
| ------------------ | ------------------------------------------------------------------------ |
| `list_drives`      | The drives shared with this connection, and which can be edited.         |
| `get_resource`     | Reads resources; documents and meetings include their text.              |
| `search`           | Full-text search.                                                        |
| `query`            | Finds resources by property values, e.g. all tasks with status "done".   |
| `find_schema`      | Searches the classes on the shared drives by words; each match comes with its JSON Schema. Search first, reuse what fits. |
| `get_user_classes` | Deprecated: `find_schema` with an empty query, as a list.                |
| `get_schema`       | The properties of a class.                                               |
| `create_resource`  | Creates one or many resources; documents take their text as `_documentText`. |
| `edit_resource`    | Sets one property, or replaces a document's text (`_documentText`).      |
| `ensure_ontology`  | Creates or updates classes from a JSON Schema (draft 2020-12). Idempotent. |
| `delete_resource`  | Deletes a resource (never a whole drive).                                |

### Schemas

Types are classes in an ontology, and an ontology is described as a JSON
Schema, the same way as in the app's assistant. Call `find_schema` first and
reuse a class that fits. Only for what is missing, call `ensure_ontology` with
`{drive, schema, shortname?}`: every object schema in `$defs` becomes a class,
`properties` become properties, `required` becomes required properties, and
constraints go in the schema as keywords (`enum`, `minimum`, `maximum`,
`minLength`, `maxLength`, `pattern`, `minItems`, `maxItems`). A
`$ref: "#/$defs/Name"` links to another class. It returns the shortname to
subject maps of the classes and properties; pass a class subject as `@class` to
`create_resource`. Calling it again with the same schema changes nothing.
Properties are identified by ontology, shortname and type, so renaming a
shortname or changing a type makes a *new* property; the old one and its data
stay. An invalid schema comes back as an error naming the JSON pointer to fix
(`oneOf`/`anyOf`/`allOf`, nullable types and nested object schemas are not
supported: move them to `$defs`). The commits are signed as the connection's
own identity, so it needs write rights on the drive.

A document's or meeting's text is written as Markdown or plain text through
`_documentText`, on `create_resource` and on `edit_resource`: headings,
paragraphs, bullet, numbered and task lists (nested by indentation), block
quotes, fenced code, rules, and inline **bold**, *italic*, ~~strike~~, `code`
and links. Every non-blank line outside a list or code block is its own
paragraph. Writing replaces the whole body, so read `_documentText` first when
keeping parts of it.

Not yet: `semantic_search` (it needs the embeddings index on the node), and
`format=compact` short references in results. See `planning/mcp-endpoint.md`.
