{{#title Atomic Data: Lenses}}

# Lenses

_status: draft_

A [Property](property-identity.md) is immutable. Renaming its shortname or changing its datatype makes a new Property with a new ID, and every value stored under the old Property is stranded.

A Lens is a declarative, content-addressed mapping between two Properties. It says how a value under `lensFrom` becomes a value under `lensTo`, and the other way around when that loses nothing. The idea comes from [Cambria](https://arxiv.org/abs/2309.11406): schema changes are translations, kept next to the schema, instead of migrations of the data.

A Lens never changes data. The signed Loro document of a resource holds only what was written. A Lens affects the **materialized** view: the property values of a resource (its propvals) that are computed from the document.

## The Lens resource

Class `https://atomicdata.dev/classes/Lens`.

| Property | Datatype | |
| --- | --- | --- |
| `lensFrom` | atomicURL | The Property the Lens reads. |
| `lensTo` | atomicURL | The Property the Lens writes. |
| `lensTransform` | json | The [transform](#transforms). |
| `parent` | atomicURL | The ontology that owns `lensTo`. |

`lensFrom`, `lensTransform`, `lensTo` and `parent` can never change after creation.

## Identifier form

```
atomic:lens:{hex}
```

`{hex}` is the 64 character lowercase hex output of BLAKE3. Parsers also accept `did:ad:lens:{hex}`. The canonical form is `atomic:lens:`.

The input is the [JCS](https://www.rfc-editor.org/rfc/rfc8785) serialization of this object. It has these three keys and no others:

```json
{
  "from": "<lensFrom>",
  "to": "<lensTo>",
  "transform": { "op": "..." }
}
```

`from` and `to` are written in their `atomic:` form first (`did:ad:` becomes `atomic:`); HTTP(S) property URLs are used as they are. They must differ. The transform is hashed in its canonical form (see [Transforms](#transforms)). The `parent` is not hashed.

BLAKE3 in derive-key mode, with this context string:

```
atomic lens identity v1
```

```
hex = BLAKE3.derive_key("atomic lens identity v1", jcs_bytes).to_hex()
id  = "atomic:lens:" + hex
```

### Test vectors

`from` is `atomic:prop:` followed by 64 times `a`. `to` is `atomic:prop:` followed by 64 times `b`.

| Transform | ID |
| --- | --- |
| `{"op":"rename"}` | `atomic:lens:ba1b06696c9786de8f0b78189d69c3aa84d59181b8eba91b7678de5959d07fcb` |
| `{"op":"rename"}`, with `from` written as `did:ad:prop:...` | `atomic:lens:ba1b06696c9786de8f0b78189d69c3aa84d59181b8eba91b7678de5959d07fcb` |
| `{"op":"wrap"}` | `atomic:lens:0e8670cccd962e1352793444a88fb841c27c39b7e74bce6b58fafbaea1056825` |
| `{"op":"map","values":{"todo":"open","done":"closed"}}` | `atomic:lens:cfbe882e5669613c8eed6dfdcaaeda204b2a5dd4d264528875911d394d2d80a5` |
| `{"op":"convert","to":"https://atomicdata.dev/datatypes/integer"}` | `atomic:lens:0201a75d08b29edddb2131fd8143349db2f8f1a3a2ab2d605a0aea9ba9262170` |

## Acceptance

A server accepts a Lens the way it accepts a content-addressed Property:

- The first commit (the genesis) has no genesis certificate. The hash of `lensFrom`, `lensTo` and `lensTransform` must equal the subject.
- The signer needs `append` rights on the `parent`.
- A second genesis for the same ID merges, under the same rights.
- `parent`, `lensFrom`, `lensTo` and `lensTransform` cannot change later.

## Transforms

`lensTransform` is a JSON object with an `op`. Unknown ops, unknown fields and invalid fields are rejected, so equal transforms have equal IDs. Each op has a **forward** direction (a `lensFrom` value to a `lensTo` value) and a **backward** direction. A direction that has nothing to say yields no value, never an error.

| Op | Forward | Backward |
| --- | --- | --- |
| `{"op":"rename"}` | The same value. | The same value. |
| `{"op":"wrap"}` | A scalar becomes a one-item array. | An array of exactly one item becomes that item. Other arrays give nothing, because the old Property cannot hold them without loss. |
| `{"op":"head"}` | An array becomes its first item. An empty array gives nothing. | A scalar becomes a one-item array. |
| `{"op":"map","values":{"a":"x"}}` | A string (or each string of an array) listed in `values` is replaced; other values pass through. | The inverse mapping. No backward direction when two keys share a value. |
| `{"op":"convert","to":"<datatype>"}` | See below. | See below, to `from` (default `string`). |

`convert` has an optional `from`, the datatype of the backward result. Both are datatype URLs and must be known datatypes.

Converting a string:

- to `integer`: the trimmed text must match `-?[0-9]+` and fit in 53 bits. `"42"` gives `42`; `"4.5"` and `"forty"` give nothing.
- to `float`: the trimmed text must match `-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
- to `boolean`: `true` or `false`, in any case.
- to a text datatype (`string`, `markdown`, `slug`, `date`, `uri`, `atomicURL`): unchanged.

Converting a number or a boolean to a text datatype writes it the way JavaScript's `String(n)` does. Nothing else converts.

## Application

A Lens is applied **at write time**, when a resource's Loro document is materialized into its propvals. Reading a materialized resource stays cheap.

After the document's own properties are materialized, for each Lens:

1. If `lensFrom` is present and `lensTo` is absent, `lensTo` becomes the forward result, if there is one.
2. If `lensTo` is present and `lensFrom` is absent, `lensFrom` becomes the backward result, if there is one.
3. Otherwise nothing happens. Both present, or neither.

"Present" means the document really holds the value. This gives these rules:

- **Real values win.** A value the document holds is never replaced. When someone writes the new Property, it takes over from the derived value.
- **Single pass, no chaining.** A derived value never feeds another Lens. A rename from `a` to `b` and another from `b` to `c` does not give `c` from `a`. Chaining is a later step.
- **Deterministic.** If two Lenses derive the same Property, the one with the smaller ID wins. The result does not depend on the order Lenses were loaded.
- **The document is untouched.** Derived values exist in the materialized view, the search index and the value index. They are not commits, are never signed and never broadcast. A removed value that was derived comes back at the next materialization; remove the real value it came from.

An old client that keeps writing the old Property is therefore visible to a new client that reads the new one, and the reverse.

### Authority

A Lens applies only when it exists in the store, its ID matches its content, and its `parent` is the `parent` of `lensTo`. A Lens never applies across an ontology it does not own: the server checks `append` on the parent when the Lens is created, and a reader checks that the parent is also the owner of the target Property. A Lens whose target Property is not known yet is inactive until it is.

Lenses never reject or alter a commit and never block sync. A Lens that cannot be applied is skipped.

### Where it happens

- **atomic_lib** keeps an in-memory index (property to Lenses) rebuilt from the stored Lens resources when the database opens. It applies Lenses when a stored resource is read, when a commit or a sync import is persisted, and indexes the derived values like real ones.
- **When a Lens arrives**, the server re-materializes the stored resources that hold `lensFrom` or `lensTo`, so the value index and search catch up. No commit is made and nothing is broadcast.
- **@tomic/lib** keeps the same index on the `Store`, filled as Lens resources load (`loadLenses` loads a drive's Lenses). It re-materializes the loaded resources that hold either Property.

Both implementations run the same cases from `lib/tests/fixtures/lenses.json`.

## Making a Lens

`ensureLens(store, { from, to, transform })` in `@tomic/lib` creates the Lens in the ontology that owns `to`, and returns the existing one when the same Lens is already there. The data browser makes one when a column or form question changes datatype (a `convert`, `wrap` or `head` lens) or gets another shortname (a `rename` lens).
