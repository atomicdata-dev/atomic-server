# Create Ontology

This skill provides a systematic procedure for building a formal Atomic Data Ontology. An ontology groups related Classes and Properties to describe a specific domain.

## Workflow / Procedure

1. **Search first.** Call `find_schema` with a few words for the thing you need (e.g. `invoice customer`). It returns the matching classes of this drive, each with its ontology and its JSON Schema. If a class fits, reuse it: use its subject, do not make a copy. If it nearly fits, say so and ask the user before making a variant.
2. **Write the new schema as JSON Schema** (draft 2020-12) and call `ensure_ontology` with it. Put every object schema in `$defs`; each becomes a class. Each entry of `properties` becomes a property, `required` the required properties, and `{"$ref": "#/$defs/Other"}` a link to another class (also to a class that `find_schema` showed you: use `x-atomic-class` with its subject).
   ```json
   {
     "title": "Shop",
     "$defs": {
       "customer": {
         "type": "object",
         "properties": { "name": { "type": "string", "minLength": 1 } },
         "required": ["name"]
       },
       "invoice": {
         "type": "object",
         "properties": {
           "amount": { "type": "number", "minimum": 0 },
           "status": { "enum": ["draft", "sent", "paid"] },
           "customer": { "$ref": "#/$defs/customer" }
         }
       }
     }
   }
   ```
3. **Pass `shortname`** (lowercase slug) to name the ontology. Without it the schema's `title` is used, and without a title the drive's default ontology. Ask the user if a new ontology is warranted when a fitting one exists.
4. **Read the result.** It maps the class and property shortnames to subjects. If it returns an `error`, it names a JSON pointer: fix that spot in your schema and call again. Unsupported: `oneOf`/`anyOf`/`allOf`, nullable types (`["string","null"]`), object schemas nested in a property (move them to `$defs`), unknown formats.
5. **Suggest further improvements** to the user when you are done.

Rules to know:

- Constraints (`enum`, `minimum`, `maximum`, `minLength`, `maxLength`, `pattern`, `minItems`, `maxItems`) go in the JSON Schema, on the property. Do not create tag resources or edit `constraints` by hand for these. For an array, put `enum` on `items`.
- It is idempotent: calling it again with the same schema changes nothing, so it is safe to retry.
- A property is identified by its ontology, shortname and type. Renaming a shortname or changing a type makes a NEW property; the old one and the data stored with it stay. Do not rename to "fix" something, add the new property and tell the user.
- Descriptions: give classes and properties a `description`; it is shown in the UI.
- `type: string` with `format: date-time` is a timestamp, `format: date` a date, `format: uri` a link; `x-atomic-datatype` (`markdown`, `slug`, `json`) picks a specific datatype.

## Manual route (only for changes `ensure_ontology` cannot express)

Use `create_resource` with the [Ontology](https://atomicdata.dev/class/ontology), [Class](https://atomicdata.dev/classes/Class) and [Property](https://atomicdata.dev/classes/Property) classes: create the ontology first and make it the parent of the classes and properties, then set each class's `requires`/`recommends`, and finally the ontology's `classes` and `properties` arrays.

## Gotchas

- **Slug Validation**: Shortnames MUST be lowercase with dashes (no CamelCase).
- **Parenting**: By creating the Ontology first, you ensure all metadata is neatly contained within the ontology's hierarchy from the start.
- **Strictness vs. Flexibility**: Use `classtype` to improve the editing UX for specific relations, but leave it empty for generic "any resource" relations.
- **Reuse Existing Properties**: Properties can be used by multiple classes. Do not create two properties for the same thing unless they mean something different. For example a `book` and `article` class can share the same `author` property but should probably not reuse it to refer to the director on a `movie` class.
- **Prefer standard properties** There are some standard properties in atomic that are prefered over more specific custom properties. These are [name](https://atomicdata.dev/properties/name) (string), [shortname](https://atomicdata.dev/properties/shortname) (slug), [image](https://atomicdata.dev/ontology/data-browser/property/image) (atomicURL pointing to a file resource) and [description](https://atomicdata.dev/properties/description) (markdown). When these are used the UI will automatically use these properties as the resource's title, description etc.
- **Search Before Create**: Never assume the drive is empty. Always call `find_schema` for existing Classes that might match the user's needs before creating new ones.
- **Don't predict new subjects**: Resources created by the `create_resource` tool will be assigned a random subject, you can not predict this beforehand and should thus wait to use it until you've actually created the resource.

## Datatypes

There are several datatypes available in Atomic Data. In Atomic, datatypes are resources and thus should be referenced by their subject e.g. `https://atomicdata.dev/datatypes/string`.
Their subject always follow the pattern `https://atomicdata.dev/datatypes/<datatype>`.

Here is a list of the available datatypes:

- `string`: A basic string.
- `markdown`: A string with markdown support. Favour this type over string for properties that will contain long text.
- `slug`: A string limited to lowercase letters and dashes.
- `uri`: A string that must be a valid URI. Rendered as a link in the UI.
- `integer`: A signed integer.
- `float`: A 64 bit decimal number.
- `boolean`: A true or false value.
- `date`: An ISO date (YYYY-MM-DD) without time.
- `timestamp`: A timestamp (milliseconds since unix epoch).
- `resourceArray`: reference to multiple resources by their subjects.
- `atomicURL`: reference to another resource by its subject.
- `json`: A JSON object.

## Creating enums

If you need to create an enum property (a property with a fixed set of allowed values), you can use the `allows-only` property.
Create a property with a datatype of `atomicUrl` and set the `allows-only` property to the subjects of the allowed values.
Usually it's best to use [tag](https://atomicdata.dev/classes/Tag) resources as values but it's perfectly valid to use other types for enum values if you need something more complex.
When creating the value resources, make sure to add them to the `instances` array of the ontology.

## Relevant schemas

Here schemas for `class`, `property` and `ontology` so you don't need to look them up.

### Class

```json
{
  "subject": "https://atomicdata.dev/classes/Class",
  "shortname": "class",
  "description": "A Class describes an abstract concept, such as 'Person' or 'Blogpost'. It describes the data shape of data (which fields are required and recommended) and explains what the concept represents. It is convention to use Uppercase in its URL.Resources use the [is-a](https://atomicdata.dev/properties/isA) attribute to indicate which classes they are instances of. Note that in Atomic Data, a Resource can have several Classes - not just a single one.",
  "required": [
    {
      "subject": "https://atomicdata.dev/properties/shortname",
      "shortname": "shortname",
      "datatype": "https://atomicdata.dev/datatypes/slug"
    },
    {
      "subject": "https://atomicdata.dev/properties/description",
      "shortname": "description",
      "datatype": "https://atomicdata.dev/datatypes/markdown"
    }
  ],
  "recommended": [
    {
      "subject": "https://atomicdata.dev/properties/recommends",
      "shortname": "recommends",
      "datatype": "https://atomicdata.dev/datatypes/resourceArray"
    },
    {
      "subject": "https://atomicdata.dev/properties/requires",
      "shortname": "requires",
      "datatype": "https://atomicdata.dev/datatypes/resourceArray"
    }
  ]
}
```

### Property

```json
{
  "subject": "https://atomicdata.dev/classes/Property",
  "shortname": "property",
  "description": "A Property is a single field in a Class. It's the thing that a property field in an Atom points to. An example is `birthdate`. An instance of Property requires various Properties, most notably a `datatype` (e.g. `string` or `integer`), a human readable `description` (such as the thing you're reading), and a `shortname`.",
  "required": [
    {
      "subject": "https://atomicdata.dev/properties/shortname",
      "shortname": "shortname",
      "datatype": "https://atomicdata.dev/datatypes/slug"
    },
    {
      "subject": "https://atomicdata.dev/properties/datatype",
      "shortname": "datatype",
      "datatype": "https://atomicdata.dev/datatypes/atomicURL"
    },
    {
      "subject": "https://atomicdata.dev/properties/description",
      "shortname": "description",
      "datatype": "https://atomicdata.dev/datatypes/markdown"
    }
  ],
  "recommended": [
    {
      "subject": "https://atomicdata.dev/properties/classtype",
      "shortname": "classtype",
      "datatype": "https://atomicdata.dev/datatypes/atomicURL"
    },
    {
      "subject": "https://atomicdata.dev/properties/allowsOnly",
      "shortname": "allows-only",
      "datatype": "https://atomicdata.dev/datatypes/resourceArray"
    }
  ]
}
```
