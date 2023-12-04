{{#title Atomic Data Translations}}
# Atomic Translations

_Status: design / concept stage_

Dealing with translations can be hard.

([Discussion](https://github.com/ontola/atomic-data/issues/6))

## TranslationBox

_URL: `https://atomicdata.dev/classes/TranslationBox` (does not resolve yet)_

A TranslationBox is a collection of translated strings, used to provide multiple translations.
It has a long list of optional properties, each corresponding to some language.
Each possible language Property uses the following URL template: `https://atomicdata.dev/languages/{langguageTag}`.
Use a [BCP 47](http://www.rfc-editor.org/rfc/bcp/bcp47.txt) language tag, e.g. `nl` or `en-US`.

For example:

```json
{
  "@id": "https://example.com/john",
  "https://example.com/properties/lifestory": {
    "https://atomicdata.dev/languages/en": "Well, John was born and later he died.",
    "https://atomicdata.dev/languages/nl": "Tsja, John werd geboren en stierf later."
  },
}
```

Every single value used for Translation strings is an instance of the Translation class.

A translation string uses the [MDString](https://atomicdata.dev/datatypes/markdown) datatype, which means it allows Markdown syntax.
