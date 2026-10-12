{{#title Atomic Data: JSON Schema}}

# JSON Schema

_status: draft_

An Ontology can be read from, and written as, a [JSON Schema](https://json-schema.org/) (draft 2020-12).
Every object schema becomes a [Class](classes.md), every entry of its `properties` becomes a [Property](property-identity.md), `required` becomes `requires`, and the keywords Atomic understands become the Class's [constraints](classes.md#constraints).

This is not a JSON Schema validator and not a complete mapping.
Import is strict: a construct Atomic cannot express is an error that names its JSON pointer, never silently dropped.

```ts
import { ensureOntology, ontologyFromJsonSchema, ontologyToJsonSchema } from '@tomic/lib';

const ontology = ontologyFromJsonSchema({
  title: 'Shop',
  'x-atomic-ontology': 'shop',
  $defs: {
    customer: {
      type: 'object',
      properties: { name: { type: 'string', minLength: 1 } },
      required: ['name'],
    },
    invoice: {
      type: 'object',
      properties: {
        amount: { type: 'number', minimum: 0 },
        customer: { $ref: '#/$defs/customer' },
      },
    },
  },
});

// Find or create the Ontology, its Properties and Classes under `drive`.
const { ontology: subject, classes, properties } = await ensureOntology(store, drive, ontology);

// And back out again.
const schema = await ontologyToJsonSchema(store, subject);
```

`ontologyFromJsonSchema` returns the input of `ensureOntology`: shortname, name, description and classes, each with its properties, `requires`, `recommends` and `constraints`.
`ensureOntology` is idempotent.
Running it twice changes nothing, and the same input gives the same `atomic:prop:` Property subjects.

Rust has the same import and `ensure_ontology` in `atomic_lib::schema::json_schema`: `ontology_from_json_schema_str` (keeps the order of the keys; `ontology_from_json_schema` takes a parsed `serde_json::Value`, whose keys are alphabetical) and `ensure_ontology(store, parent, plan, agent)`.
Export is TypeScript only.
Both implementations run the cases in `lib/tests/fixtures/json-schema-interop.json`.

## Mapping

| JSON Schema | Atomic |
| --- | --- |
| Object schema in `$defs` | Class. The shortname is the key as a slug (`LineItem` becomes `line-item`), the name is the `title`, else the key |
| Root schema with `properties` | Class, named after the `title` |
| Root `title`, `description` | Ontology `name`, `description` |
| Root `x-atomic-ontology`, else slugified `title` | Ontology `shortname` |
| `properties` entry | Property, shortname is the key as a slug; `title` is its `name`, `description` its `description` |
| `required` | Class `requires`. The other properties are `recommends` |
| `type: string` | `string` |
| `type: string, format: date-time` | `timestamp` |
| `type: string, format: date` | `date` |
| `type: string, format: uri` | `atomicURL` |
| `type: integer` | `integer` |
| `type: number` | `float` |
| `type: boolean` | `boolean` |
| `$ref: "#/$defs/Name"` | `atomicURL` plus a `class` constraint pointing at that Class |
| `type: array` of `$ref` | `resourceArray` plus a `class` constraint |
| `type: array` of `{ type: string, format: uri }` | `resourceArray` |
| Other `type: array`, `type: object` | `json` |
| `enum`, `const` | `enum` constraint. Without a `type` the datatype follows the values. On an array, put it on `items` |
| `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum` | the same constraint keyword |
| `minLength`, `maxLength`, `pattern` | the same constraint keyword |
| `minItems`, `maxItems` | the same constraint keyword |

The constraints are stored on the Class, keyed by the property's subject, not on the Property: Properties are immutable and only their shortname and datatype are part of their identity.
That also means two classes that both declare `name` as a string share one Property and can still constrain it differently.

`$comment`, `examples`, `default`, `deprecated`, `readOnly`, `writeOnly` and a root `$id` are annotations.
They are read and dropped.
`additionalProperties` may be a boolean and is dropped: Atomic classes are open.

## What does not map

Each of these is an error on import, naming the keyword's JSON pointer, for example `/$defs/Invoice/properties/status/oneOf`.

- `oneOf`, `anyOf`, `allOf`, `not`, `if`/`then`/`else`, `dependentSchemas`, `patternProperties`, `propertyNames`, `unevaluated*`, `prefixItems` and the other keywords that Atomic has no equivalent for.
- Nullable types (`type: ["string", "null"]`). Atomic has no null: leave the property out of the value instead.
- A `$ref` that is not a local `#/$defs/Name` to an object schema, a `$defs` entry that is not an object schema, and any keyword next to `$ref` other than `title`, `description` and `enum`.
- Object schemas nested inside a property (`properties` below a property). Move them to `$defs` and `$ref` them.
- `enum` or `const` on an array. It constrains the whole array in JSON Schema, but a class constraint applies to every item. Put it on `items`.
- A `format` other than `date-time`, `date` and `uri`, and any `type` other than `string`, `integer`, `number`, `boolean`, `array` and `object`.
- Boolean schemas, a `$schema` other than draft 2020-12, unknown `x-` keywords, and any other keyword.
- A property name that cannot become a [slug](datatypes.md#slug), two names that become the same shortname, and a shortname used with two datatypes in one Ontology (a Property is identified by shortname and datatype, and an Ontology cannot hold two with one shortname).

Items of a `json` array are not described: `{ type: array, items: { type: string } }` imports as plain `json`.

## `x-atomic-*` keywords

These carry what JSON Schema cannot say, so that an export imports again as the same Ontology.

| Keyword | Where | Meaning |
| --- | --- | --- |
| `x-atomic-ontology` | root | The Ontology's shortname |
| `x-atomic-datatype` | property | The exact Atomic datatype, when `type` and `format` are not enough: `markdown`, `slug`, `uri`, `json`, `lorodoc`, `localizedText`. Wins over the datatype that `type` implies |
| `x-atomic-class` | property, or `items` of an array | The `class` constraint of a link, for a class outside the schema (a subject), or a class in it (a shortname) |
| `x-atomic-property` | property, export only | The property's `atomic:prop:` subject |
| `x-atomic-subject` | root and classes, export only | The Ontology's or Class's subject |

`x-atomic-property` and `x-atomic-subject` are for readers.
Import ignores them: a Property's identity follows from its Ontology, shortname and datatype, and is never taken on trust from a document.

## Export

`ontologyToJsonSchema(store, ontology)` writes a draft 2020-12 schema with one `$defs` entry per Class and `properties` keyed by shortname.
A `class` constraint on a Class of the same Ontology becomes a `$ref` to its entry, any other becomes `x-atomic-class`.

Import followed by `ensureOntology` followed by export gives the input back, with these normalisations:

- `$defs` keys are the class name when that is an identifier whose slug is the shortname (`LineItem`), else the shortname. Property keys are always shortnames: `unitPrice` becomes `unit-price`.
- `title` is left out when it equals the key or shortname, and `description` when it equals the name.
- A `json` property is written as `{ "x-atomic-datatype": "json" }`, without its `type`.
- `const` becomes a one-item `enum`, and an `enum` without a `type` gains the type of its values.
- Annotations and `additionalProperties` are gone, `required: []` is omitted, and `$schema`, `x-atomic-ontology`, `x-atomic-subject` and `x-atomic-property` are added.
- A property shared by two classes has one `title` and `description`: those of the first class that declared it.

An export is a fixed point: importing it and exporting again changes nothing.

## Schemas from the command line

Write the schema in your own language, run one command, get a real ontology and a lockfile that pins its property IDs, then generate types.
The file is either a JSON Schema (it has `$schema` or `$defs`, or is `type: object`) or an `OntologyInput` JSON (`{ "shortname": ..., "classes": [...] }`).
Both command line tools do the same; the lockfile they write is byte for byte the same.

```sh
# Rust CLI (atomic-cli), uses the server and agent in its config
atomic-cli schema push shop.schema.json --parent <drive subject>
atomic-cli schema lock shop.schema.json --ontology <ontology subject>   # offline
atomic-cli schema check shop.schema.json                                # offline

# @tomic/cli, uses atomic.config.json (serverUrl, agentSecret)
npx ad-generate ontology push shop.schema.json --parent <drive subject> --types
npx ad-generate ontology lock shop.schema.json --ontology <ontology subject>
npx ad-generate ontology check shop.schema.json
```

- `push` runs `ensureOntology`: it creates the ontology under `--parent`, or finds it again, and brings classes in line. It then writes the lockfile. `atomic-cli` takes the parent from the config's initial drive when `--parent` is left out. `--types` (`@tomic/cli` only) adds the ontology to `atomic.config.json` and generates the TypeScript types.
- `lock` needs no server. Property IDs follow from the ontology subject, the shortname and the datatype, so the lockfile can be made as soon as you know the ontology's subject. Class subjects are minted by the server, so they stay empty until a `push`. Locking again keeps the class subjects of an earlier push of the same ontology.
- `check` fails when the lockfile no longer matches the schema. Changing a property's shortname or datatype makes a new property with a new ID, and `check` says so. Commit the lockfile and run `check` in CI.
- `push` refuses to run when the existing lockfile fails `check`, so a changed datatype cannot quietly create a second property. `--accept-changes` pushes anyway.
- `--shortname` overrides the ontology's shortname, `--lockfile <path>` the lockfile's location.

The lockfile is `<file>.lock.json` next to the schema file (`shop.schema.json.lock.json`). Its keys are sorted, it is indented with two spaces and ends with a newline:

```json
{
  "classes": {
    "customer": "did:ad:..."
  },
  "ontology": "did:ad:...",
  "properties": {
    "email": "atomic:prop:b4152651d32b39d8d89901323c9673775d2e43bb2ea452db01c8ad5d52432bc1",
    "name": "atomic:prop:f04459be53adc3c4904126504db01a55e68a0932d3fd054fa8a5eb4b5bdd5d16"
  }
}
```

`atomic-cli` finds the ontology of a re-run through the `ontology` in the lockfile, because it cannot query the server for it. Keep the lockfile, or the next `push` makes a second ontology. `@tomic/cli` finds it by shortname under `--parent`.

In code: `lockfileFromInput`, `serializeLockfile`, `checkLockfile` in `@tomic/lib`, and `Lockfile` in `atomic_lib::schema::lockfile`.
