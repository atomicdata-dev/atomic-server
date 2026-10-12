# Storage per chat message

> **Status:** Partial (2026-10-05). Steps 1 to 5 are done; 6 to 8 are open.

A chat message with the text "hallo" took about 10.7 KB in the server store.
Measured with the ignored test `measure_chat_message_bytes`
(`lib/src/db/test.rs`): 50 messages in one chat, bytes per tree, with the
compressed trees counted as stored. Run it with
`cargo test -p atomic_lib --features db-redb --lib -- measure_chat_message_bytes --ignored --nocapture`.

The same signed data was kept four times (stored resource, genesis commit row,
envelope, Loro snapshot) and the two atom indexes wrote ten rows each.

| per message | start | now |
| --- | --- | --- |
| resources (message row + genesis commit row) | 2.7 KB | 1.7 KB |
| Loro snapshot | 1.5 KB | 0.3 KB |
| envelope | 2.4 KB | 0 |
| `PropValSub` | 1.9 KB | 0.7 KB |
| `ValPropSub` | 1.9 KB | 0.4 KB |
| search | 0.3 KB | 0.3 KB |
| **total** | **10.7 KB** | **3.5 KB** |

## Done

1. **Compress** resources, snapshots and envelopes (`db/compressed_kv.rs`). A
   marker byte keeps old rows readable.
2. **One copy of the genesis commit.** Its envelope is not written; the
   `Tree::Resources` commit row is the durable record and `envelopes()` rebuilds
   the envelope from it (`envelopes.rs`). Under `All` retention the first later
   commit writes it out.
3. **A creation's commit atoms are not indexed.** The commit is found by its id.
   Rights, parent and destroy commits are still indexed by subject.
4. **`ValPropSub` only holds references.** It answers "what points at X". Text,
   numbers and timestamps (`is_reference`) have no row. A value-only query
   (`value` without `property`) on a text value no longer finds new resources;
   nothing in the app issues one.
5. **The snapshot is a delta on the genesis commit.** The commit row already
   keeps the signed `loroUpdate`; the snapshot keeps only what came after it
   (`db/compressed_kv.rs`, codec 2) and a read puts the two back together. Whole
   snapshot when the commit row is missing (arrived by sync) or the rebuild
   does not match.

Old rows are left as they are; they go when their resource changes.

## Open

6. **Shorter index keys (about 0.3 KB).** The `https://atomicdata.dev/properties/`
   prefix as one byte, and the subject as 64 raw bytes (last field, so a `0xff`
   inside it cannot break the split). Needs both key forms deleted on removal,
   as for the legacy sort part, and the indexes rebuilt on upgrade.
7. **What is left is the signed Loro update** (commit row, about 1.1 KB) **and
   the message row** (0.4 KB). Every property key is a full URL inside
   the document, and a `datatypes` entry sits beside it. Short keys inside the
   document would cut each copy by roughly a quarter, but that changes what
   clients sign and send, so it needs a protocol version, not a migration.
8. **Search** (`SearchDocs` keeps the tokens a delete needs): 0.2 KB, could be
   recomputed from the resource on delete instead.

The snapshot cannot be dropped for a resource nobody has edited: it also holds
the changes the server writes (`lastCommit`, derived `drive`), which exist
nowhere else; the delta keeps just those.

## Property dictionary (design, 2026-10-05)

Per-row breakdown of one "hallo" message (3195 B): message row 439, genesis
commit row 1163, snapshot delta 347, `PropValSub`/`ValPropSub` about 1100,
search 148. Full property URLs and the 93 B subject repeat in nearly every row.

Two layers, the safe one first.

1. **Database dictionary (no protocol change).** A small tree maps each
   property URL and datatype tag to a 1 to 2 byte id, with an in-memory cache.
   Used by index keys, resource rows and the snapshot delta. A marker byte keeps
   old rows readable, as with compression. Open question: deflate on a 350 B row
   learns little, so a static substitution codec for well-known URLs before
   deflate may beat a learned dictionary for values; index keys need the id map
   either way.
2. **Short keys in the protocol (HDT-like).** The Loro document and the signed
   commit use ids from a fixed, published dictionary of well-known properties;
   custom properties keep their URL. Changes what clients sign, so it needs a
   protocol version and the old form keeps working.

Layer 1 first: measure per tree, build in its own PR. Layer 2 needs Joep's go on
the versioning approach before code.
