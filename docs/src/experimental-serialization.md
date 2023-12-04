# Experimental Atomic Data serialization formats

These experimental formats are not supported or maintained. This document serves as an archived reference.

## AD3 (Deprecated)

_AD3 is now deprecated in favor of JSON-AD_

AD3 stands for _Atomic Data Triples_, and it's the simplest and fastest way to serialize / parse Atomic Data.

AD3 represents a single Atom as a single line, containing a JSON array of three strings, respectively representing the Subject, Property and Value.

It looks like this:

```ad3
["https://example.com/subject","https://example.com/property","some object"]
["https://example.com/subject","https://example.com/otherProperty","https://example.com/somethingelse"]
```

It uses Newline Delimited JSON ([NDJSON](http://ndjson.org/)) for serialization, which is just a large string with newlines between each JSON object.

NDJSON has some important benefits:

- **Streaming parsing**: An NDJSON document can be parsed before it's fully loaded / transmitted. That is not possible with regular JSON.
- **High compatibility**: NDJSON parsers can use JSON parsers, and are therefore everywhere.
- **Performance**: Modern browsers have highly performant JSON parsing, which means that it's _fast_ in one of the most important contexts: the browser.

_Mime type (not registered yet!): `application/ad3-ndjson`_

_File name extension: `.ad3`_

Disclaimer: note that AD3 is useful for communicating _current state_, but not for _state changes_.

You can validate AD3 at [atomicdata.dev/validate](https://atomicdata.dev/validate).

Atomic Triples is heavily inspired by [HexTuples-NDJSON](https://github.com/ontola/hextuples).

Example serialization implementation written in Rust, to show you how _easy_ it is to serialize this!

```rust
pub fn serialize_atoms_to_ad3(atoms: Vec<Atom>) -> AtomicResult<String> {
    let mut string = String::new();
    for atom in atoms {
        // Use an exsting JSON serialization library to take care of the hard work (escaping quotes, etc.)
        let mut ad3_atom = serde_json::to_string(&vec![&atom.subject, &atom.property, &atom.value])?;
        ad3_atom.push_str("\n");
        &string.push_str(&*ad3_atom);
    }
    return Ok(string);
}
```

And an example parser:

```rust
pub fn parse_ad3<'a, 'b>(string: &'b String) -> AtomicResult<Vec<Atom>> {
    let mut atoms: Vec<Atom> = Vec::new();
    for line in string.lines() {
        match line.chars().next() {
            // These are comments
            Some('#') => {}
            Some(' ') => {}
            // That's an array, let's do this!
            Some('[') => {
                let string_vec: Vec<String> =
                    parse_json_array(line).expect(&*format!("Parsing error in {:?}", line));
                if string_vec.len() != 3 {
                    return Err(format!(
                        "Wrong length of array at line {:?}: wrong length of array, should be 3",
                        line
                    )
                    .into());
                }
                let subject = &string_vec[0];
                let property = &string_vec[1];
                let value = &string_vec[2];
                atoms.push(Atom::new(subject, property, value));
            }
            Some(char) => {
                return Err(format!(
                    "AD3 Parsing error at {:?}, cannot start with {}",
                    line, char
                )
                .into())
            }
            None => {}
        };
    }
    return Ok(atoms);
}
```

## AD2

AD2 (Atomic Data Doubles) is similar to AtomicTriples, with one exception: the Subject is left out.
For many use-cases, omitting the Subject is a _bad idea_ - you'll most often need AD2!
having no subject means that you can't describe multiple resources in a single document, and that is useful in many contexts.

However, omitting the subject can be useful in (at least) three scenarios:

- The **Subject is not yet known when creating the data** (for example, because it still has to be determined by some server or hash function).
- The **Subject is already known by the client**, and leaving it out saves bandwidth. This happens for example during Subject Fetching, where the request itself contains the Subject, because the fetched URL itself is the Subject of all returned triples. Note that in this scenario, the server is unable to include
- The **Atoms are only valid coming from a specific source**. Since

```ndjson
["https://example.com/property","some object"]
["https://example.com/otherProperty","https://example.com/somethingelse"]
```

Keep in mind that this approach also has some downsides:

- It becomes impossible to include other resources in a single serialized document / response.

- _Mime type (not registered yet!): `application/ad2-ndjson`_
- _File name extension: `.ad2`_

### AtomicData-FS

Possible extension: `.adf`

FS stands for FileSystem.
It should be designed as a format that's easy to manipulate Atomic Data by hand, using plaintext editors and IDE software.
It fits nicely in our line-based paradigm, where we us IDEs and Github to manage our information.
It should use Shortnames wherever possible to make life easier for those who modify instances.
It might use hierarchical path structures to shape URLs.
It might use hierarchical path structures to shape data, and set constraints (e.g. all items directly in the `./person` directory should be Person instances).
Folder structure should reflect the structure inside URLs.

Note that this format is _not_ useful for sending arbitrary Atomic Data to some client.
It is useful for managing Atomic Data from a filesystem.

An example AtomicData-FS dir can be [found in the repo](https://github.com/ontola/atomic-data/tree/master/examples/atomic-fs/people).

```
# in ./projectDir/people/john.adf
# serialization uses YAML syntax
firstName: John
lastName: McLovin
# If a Property is not available in the Class, you can the URL of the property
https://schema.org/birthDate: 1991-01-20
# Perhaps support relative paths to other local resources
bestFriend: ./mary
```

Perhaps YAML isn't the right pick for this, because it's kind of hard to parse.

### AtomicData-Binary

Possible extension: `.adb`

A binary serialization format, designed to be performant and highly compressed.
Perhaps it works like this:

- An `adb` file consists of a large sequence of Maps and Statements
- A _Map_ is a combination of an internal identifiers (the _ID_, some short binary object) and a URL strings. These make sure that URLs can be used again cheaply, if they are used multiple times.
- A _Statement_ is a set of two IDs and a value, which can be a String, a URL or some binary format.
- Perhaps some extra compression is possible, because many URLs will have a common domain.
