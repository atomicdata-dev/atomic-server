{{#title Atomic Data Classes}}
# Atomic Schema: Classes

The following Classes are some of the most fundamental concepts in Atomic Data, as they make data validation possible.

Click the URLs of the classes to read the most actual data, and discover their properties!

## Property

_URL: [`https://atomicdata.dev/classes/Property`](https://atomicdata.dev/classes/Property)_

The Property class.
The thing that the Property field should link to.
A Property is an abstract type of Resource that describes the relation between a Subject and a Value.
A Property provides some semantic information about the relationship (in its `description`), it provides a shorthand (the `shortname`) and it links to a Datatype.

Properties of a Property instance:

- [`shortname`](https://atomicdata.dev/properties/shortname) - (required, Slug) the shortname for the property, used in ORM-style dot syntax (`thing.property.anotherproperty`).
- [`description`](https://atomicdata.dev/properties/description) - (optional, AtomicURL, TranslationBox) the semantic meaning of the.
- [`datatype`](https://atomicdata.dev/properties/datatype) - (required, AtomicURL, Datatype) a URL to an Atomic Datatype, which defines what the datatype should be of the Value in an Atom where the Property is the
- [`classtype`](https://atomicdata.dev/properties/classtype) - (optional, AtomicURL, Class) if the `datatype` is an Atomic URL, the `classtype` defines which class(es?) is (are?) acceptable.

```json
{
  "@id": "https://atomicdata.dev/properties/description",
  "https://atomicdata.dev/properties/datatype": "https://atomicdata.dev/datatypes/markdown",
  "https://atomicdata.dev/properties/description": "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.",
  "https://atomicdata.dev/properties/isA": [
    "https://atomicdata.dev/classes/Property"
  ],
  "https://atomicdata.dev/properties/shortname": "description"
}
```

Visit the [Properties Collection](https://atomicdata.dev/properties) for a list of example Properties.

## Datatype

_URL: [`https://atomicdata.dev/classes/Datatype`](https://atomicdata.dev/classes/Datatype)_

A Datatype specifies how a `Value` value should be interpreted.
Datatypes are concepts such as `boolean`, `string`, `integer`.
Since DataTypes can be linked to, you dan define your own.
However, using non-standard datatypes limits how many applications will know what to do with the data.

Properties:

- `description` - (required, AtomicURL, TranslationBox) how the datatype functions.
- `stringSerialization` - (required, AtomicURL, TranslationBox) how the datatype should be parsed / serialized as an UTF-8 string
- `stringExample` - (required, string) an example `stringSerialization` that should be parsed correctly
- `binarySerialization` - (optional, AtomicURL, TranslationBox) how the datatype should be parsed / serialized as a byte array.
- `binaryExample` - (optional, string) an example `binarySerialization` that should be parsed correctly. Should have the same contents as the stringExample. Required if binarySerialization is present on the DataType.

Visit [the Datatype collection](https://atomicdata.dev/collections/datatype) for a list of example Datatypes.

## Class

_URL: [`https://atomicdata.dev/classes/Class`](https://atomicdata.dev/classes/Class)_

A Class is an abstract type of Resource, such as `Person`.
It is convention to use an Uppercase in its URI.
Note that in Atomic Data, a Resource can have several Classes - not just a single one.
If you need to set more complex constraints to your Classes (e.g. maximum string length, Properties that depend on each other), check out [SHACL](https://www.w3.org/TR/shacl/).

Properties:

- `shortname` - (required, Slug) a short string shorthand.
- `description` - (required, AtomicURL, TranslationBox) human readable explanation of what the Class represents.
- `requires` - (optional, ResourceArray, Property) a list of Properties that are required. If absent, none are required. These SHOULD have unique shortnames.
- `recommends` - (optional, ResourceArray, Property) a list of Properties that are recommended. These SHOULD have unique shortnames.
<!-- - `deprecatedProperties` - (optional, ResourceArray, Property) - a list of Properties that should no longer be used. -->
<!-- Maybe remove this next one? -->
<!-- - `disallowedProperties` - (optional, ResourceArray) a list of Properties that are not allowed.  If absent, all are allowed. -->
<!-- What are the consequences of this? How to deal with this field if there are more classes in aSSubject? -->
<!-- - `allowedProperties` - (optional, ResourceArray) a list of Properties that are allowed. If absent, none are required. -->

A resource indicates it is an _instance_ of that class by adding a `https://atomicdata.dev/properties/isA` Atom.

Example:

```json
{
  "@id": "https://atomicdata.dev/classes/Class",
  "https://atomicdata.dev/properties/description": "A Class describes an abstract concept, such as 'Person' or 'Blogpost'. It describes the data shape of data and explains what the thing represents. It is convention to use Uppercase in its URL. Note that in Atomic Data, a Resource can have several Classes - not just a single one.",
  "https://atomicdata.dev/properties/isA": [
    "https://atomicdata.dev/classes/Class"
  ],
  "https://atomicdata.dev/properties/recommends": [
    "https://atomicdata.dev/properties/recommends",
    "https://atomicdata.dev/properties/requires",
    "https://atomicdata.dev/properties/constraints"
  ],
  "https://atomicdata.dev/properties/requires": [
    "https://atomicdata.dev/properties/shortname",
    "https://atomicdata.dev/properties/description"
  ],
  "https://atomicdata.dev/properties/shortname": "class"
}
```

Check out a [list of example Classes](https://atomicdata.dev/classes/).

## Constraints

A Class can restrict the values its instances may hold with the [`constraints`](https://atomicdata.dev/properties/constraints) property (datatype `json`, recommended on Class).
Properties are immutable, so everything beyond a Property's shortname and datatype lives here, the way JSON Schema keeps `enum` or `minimum` inside an object's `properties` instead of on a global field.

The value is a JSON object keyed by property subject.
Use the canonical `atomic:` form for Atomic identifiers (`did:ad:` is read as `atomic:`) and the URL as-is for HTTP subjects.
Each value is an object of the keywords below.

| Keyword | Value | Applies to | Breaks when |
| --- | --- | --- | --- |
| `enum` | array | any value; every item of an array | the value is not one of the listed values |
| `minimum` | number | numbers | value `<` minimum |
| `maximum` | number | numbers | value `>` maximum |
| `exclusiveMinimum` | number | numbers | value `<=` the bound |
| `exclusiveMaximum` | number | numbers | value `>=` the bound |
| `minLength` | integer `>= 0` | strings | fewer Unicode code points than the bound |
| `maxLength` | integer `>= 0` | strings | more Unicode code points than the bound |
| `minItems` | integer `>= 0` | arrays | fewer items than the bound |
| `maxItems` | integer `>= 0` | arrays | more items than the bound |
| `pattern` | regex string | strings | the string has no match (unanchored, like JSON Schema) |
| `class` | class subject | links | never checked, see below |

These are JSON Schema keywords with the same meaning, except that `class` stands in for `$ref` and `enum` also accepts a list of subjects.
A keyword that does not apply to the value's type is ignored, as in JSON Schema: `minimum` on a string does nothing.
Numbers compare by value (`1` equals `1.0`), and subjects compare after `did:ad:` is read as `atomic:`.
Unknown keywords are rejected when the Class is written, so a typo like `minimun` fails loudly.

`pattern` uses the subset shared by Rust's `regex` crate and JavaScript without flags: literals, `.`, character classes, `^` and `$`, groups, `|`, and the quantifiers `* + ? {n,m}`.
Avoid lookaround and backreferences (Rust rejects them) and write `[0-9]` instead of `\d`, since `\d`, `\w` and `\s` are Unicode-aware in Rust and ASCII-only in JavaScript.

`class` names the class a link should point to.
It is for pickers and forms, like `classtype` on a Property, and is **not** enforced when a value is written.

### Enforcement

- **Commit time.** The server checks every value of a resource against the constraints of each class in its `isA`, next to the check for `requires`, and rejects the commit with `Value for <shortname> breaks <keyword> on class <class shortname>: <detail>`.
  A Class commit is rejected when its own `constraints` map has an unknown keyword or a wrong type.
- **Never on sync.** Reconciling drives and importing peer data does not run these checks, and neither do commits received over a peer connection. A replica keeps what another node already accepted.
- **Unloaded classes are skipped in the client.** Before signing, `@tomic/lib` runs the same checks for classes already in the local store and throws the same message. It never fetches a class for this, so the server stays the authority.
- **Legacy.** A Property's own `allowsOnly` and `max` keep working as before and are still not enforced.

Both implementations (`atomic_lib` and `@tomic/lib`) run the same cases from `lib/tests/fixtures/class-constraints.json`.

### Example

```json
{
  "@id": "https://example.com/classes/Invoice",
  "https://atomicdata.dev/properties/isA": ["https://atomicdata.dev/classes/Class"],
  "https://atomicdata.dev/properties/shortname": "invoice",
  "https://atomicdata.dev/properties/description": "A bill.",
  "https://atomicdata.dev/properties/constraints": {
    "https://example.com/properties/status": { "enum": ["atomic:tag:draft", "atomic:tag:sent"], "maxItems": 1 },
    "https://example.com/properties/amount": { "minimum": 0, "maximum": 10000 },
    "https://example.com/properties/number": { "pattern": "^INV-[0-9]{4}$" },
    "https://example.com/properties/customer": { "class": "https://example.com/classes/Customer" }
  }
}
```

An invoice with `amount` `-5` is rejected with `Value for amount breaks minimum on class invoice: -5 is below 0`.
