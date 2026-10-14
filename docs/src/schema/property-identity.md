{{#title Atomic Data: Property identity}}

# Property identity

_status: draft_

A Property is immutable and content-addressed. Its ID is a hash of exactly three fields: the namespace it belongs to, its shortname, and its datatype.

The namespace is the resource the Property belongs to: its `parent`. This is usually an Ontology. It can also be a Class acting as one, for example a table column whose table has no Ontology. In the hash this field is called `ontology`.

Two Properties with the same namespace, shortname and datatype are the same Property. Change any of the three and you get a new Property with a new ID. So `parent`, `shortname` and `datatype` can never change after creation.

Values stored under the old Property stay where they are. A [Lens](lenses.md) maps them onto the new one.

## Identifier form

```
atomic:prop:{hex}
```

`{hex}` is the 64 character lowercase hex output of BLAKE3. This matches `atomic:blob:{blake3-hex}` (see [Identifiers](../identifiers.md)).

Parsers also accept `did:ad:prop:{hex}`. The canonical form is `atomic:prop:`. The two spellings name the same Property.

When the ID is used as a property key, always write it in the `atomic:prop:` form. Loro property-map keys are not canonicalized, so a `did:ad:prop:` key would be a different key from the `atomic:prop:` one.

## What is hashed

The input is the JSON Canonicalization Scheme (JCS, RFC 8785) serialization of this object. It has these three keys and no others:

```json
{
  "datatype": "<datatype URL>",
  "ontology": "<ontology ID>",
  "shortname": "<shortname>"
}
```

JCS sorts the keys and removes whitespace, so the hashed bytes look like this:

```
{"datatype":"<datatype URL>","ontology":"<ontology ID>","shortname":"<shortname>"}
```

## Normalization

Apply these rules before hashing. Reject the input if a rule fails.

- **Ontology (the namespace).** If it is a `did:ad:` identifier, rewrite it to its `atomic:` form. HTTP(S) ontology URLs are used as they are.
- **Shortname.** It must be a valid [slug](datatypes.md#slug): `^[a-z0-9]+(?:-[a-z0-9]+)*$`.
- **Datatype.** It must be the URL of a known [datatype](datatypes.md). Unknown datatype URLs are rejected.

## Hash function

BLAKE3 in derive-key mode, with this context string:

```
atomic property identity v1
```

The context separates property IDs from blob hashes. A property ID can never equal the hash of a blob, even if the bytes are the same.

```
hex = BLAKE3.derive_key("atomic property identity v1", jcs_bytes).to_hex()
id  = "atomic:prop:" + hex
```

## Shared vocabularies and the drive's own ontology

Because the namespace is part of the hash, the same field created in two ontologies is two different Properties. A table template that created its columns in each drive's own ontology would give "Email" a different ID on every drive, and data from two drives would not line up.

Table templates therefore split their schema in two:

- **Generic fields live in a shared vocabulary.** A shared vocabulary is a small, versioned, immutable set of Properties with a fixed namespace, for example `https://atomicdata.dev/work/v1/` (start, end, project, person, billable), `contact/v1` (email, company), `pipeline/v1` (stage) and `money/v1` (amount). Every AtomicServer embeds these definitions, so they resolve on any drive, also offline, without fetching atomicdata.dev. The Time tracker, Expenses, Deals (CRM), Job applications and Guest list templates use them. The Issue Tracker and Project tasks templates use `task/v1` the same way.
- **The drive keeps its own ontology.** The template's row Class (for example "Deal") and any field that is specific to the template or added later are created in the drive's default ontology. The row Class lists the shared Properties like any other Property.

Constraints are not part of a Property's identity, so they stay on the row Class. A "Stage" column with the options Lead, Contacted and Won on one drive and Wishlist, Applied and Offer on another uses the same `pipeline/v1/stage` Property, and each Class holds its own options.

A shared Property never changes after release. A different shortname or datatype is a new Property in a new version of the vocabulary (`v2`), mapped with a [Lens](lenses.md). Tables created before a template moved to a shared vocabulary keep their drive-local Properties; they are not migrated automatically.

## What is not hashed

Labels and descriptions are not part of the identity. They stay editable. Fixing a typo in a description does not change the ID.

Other constraints are not part of the identity either. This covers allowed values, class type, minimum and maximum. They belong to the Class that uses the Property, not to the Property itself.

JSON Schema works the same way. Keywords such as `enum` and `minimum` sit inside an object's `properties`, next to the property name, and not on a shared definition of that name. A Class lists its Properties and says which values each may take. Two Classes can then allow different values for the same Property without needing two Properties.

## Verification

Given a subject, an ontology, a shortname and a datatype, a verifier normalizes the inputs, computes the ID, and compares it with the subject after canonicalizing the scheme. Both `atomic:prop:` and `did:ad:prop:` subjects are accepted.

## Test vectors

All use the shortname `name`.

| Ontology | Datatype | ID |
| --- | --- | --- |
| `atomic:ontologyGenesis` | `https://atomicdata.dev/datatypes/string` | `atomic:prop:5a939a7ca63806573c204c88e8994252ef6e14f125f8bd258bce672344b2ba74` |
| `did:ad:ontologyGenesis` | `https://atomicdata.dev/datatypes/string` | `atomic:prop:5a939a7ca63806573c204c88e8994252ef6e14f125f8bd258bce672344b2ba74` |
| `https://atomicdata.dev/ontology/core` | `https://atomicdata.dev/datatypes/string` | `atomic:prop:2476b0c536e851a71bc0c1991bf3746c9370085c3e6e52a0dd8255e61be1a862` |
| `atomic:ontologyGenesis` | `https://atomicdata.dev/datatypes/slug` | `atomic:prop:d744c0c58cf42bff6246a015b5e1429c93f1ca505c3355dd84c695c8da6e6626` |

Rows 1 and 2 show that `did:ad:` ontologies normalize to the `atomic:` form. Rows 1 and 4 differ only in datatype, and so have different IDs.
