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
    "https://atomicdata.dev/properties/requires"
  ],
  "https://atomicdata.dev/properties/requires": [
    "https://atomicdata.dev/properties/shortname",
    "https://atomicdata.dev/properties/description"
  ],
  "https://atomicdata.dev/properties/shortname": "class"
}
```

Check out a [list of example Classes](https://atomicdata.dev/classes/).
