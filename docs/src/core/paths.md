{{#title Atomic Data Paths}}
# Atomic Paths

An Atomic Path is a string that consists of at least one URL, followed by one or more URLs or Shortnames.
Every single value in an Atomic Resource can be targeted through such a Path.
They can be used as identifiers for specific Values.

The simplest path, is the URL of a resource, which represents the entire Resource with all its properties.
If you want to target a specific atom, you can use an Atomic Path with a second URL.
This second URL can be replaced by a Shortname, if the Resource is an instance of a class which has properties with that Shortname (sounds more complicated than it is).

## Example

Let's start with this simple Resource:

```json
{
  "@id": "https://example.com/john",
  "https://example.com/lastName": "McLovin",
}
```

Then the following Path targets the `McLovin` value:

`https://example.com/john https://example.com/lastName` => `McLovin`

Instead of using the full URL of the `lastName` Property, we can use its [shortname](https://atomicdata.dev/properties/shortname):

`https://example.com/john lastname` => `McLovin`

We can also traverse relationships between resources:

```json
[{
  "@id": "https://example.com/john",
  "https://example.com/lastName": "McLovin",
  "https://example.com/employer": "https://example.com/XCorp",
},{
  "@id": "https://example.com/XCorp",
  "https://example.com/description": "The greatest company!",
}]
```

`https://example.com/john employer description` => `The greatest company!`

In the example above, the XCorp subject exists and is the source of the `The greatest company!` value.
We can use this path as a unique identifier for the description of John's current employer.
Note that the data for the description of that employer does not have to be in John's control for this path to work - it can live on a totally different server.
However, in Atomic Data it's also possible to include this description in the resource of John as a _Nested Resource_.

## Nested Resources

All Atomic Data Resources that we've discussed so far have an explicit URL as a subject.
Unfortunately, creating unique and resolvable URLs can be a bother, and sometimes not necessary.
If you've worked with RDF, this is what Blank Nodes are used for.
In Atomic Data, we have something similar: _Nested Resources_.

Let's use a Nested Resource in the example from the previous section:

```json
{
  "@id": "https://example.com/john",
  "https://example.com/lastName": "McLovin",
  "https://example.com/employer": {
    "https://example.com/description": "The greatest company!",
  }
}
```

Now the `employer` is simply a nested Object.
Note that it no longer has its own `@id`.
However, we can still identify this Nested Resource using its Path.

The Subject of the nested resource is its path: `https://example.com/john https://example.com/employer`, including the spacebar.

Note that the path from before still resolves:

`https://example.com/john employer description` => `The greatest company!`

## Traversing Arrays

We can also navigate Arrays using paths.

For example:

```json
{
  "@id": "https://example.com/john",
  "hasShoes": [
    {
      "https://example.com/name": "Mr. Boot",
    },
    {
      "https://example.com/name": "Sunny Sandals",
    }
  ]
}
```

The Path of `Mr. Boot` is:

```
https://example.com/john hasShoes 0 name
```

You can target an item in an array by using a number to indicate its position, starting with 0.

Notice how the Resource with the `name: Mr. Boot` does not have an explicit `@id`, but it _does_ have a Path.
This means that we still have a unique, globally resolvable identifier - yay!

## Try for yourself

Install the [`atomic-cli`](https://github.com/atomicdata-dev/atomic-server/blob/master/cli/README.md) software and run `atomic-cli get https://atomicdata.dev/classes/Class description`.
