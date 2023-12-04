# Atomic Schema compared to alternatives

Introducing yet another Schema language might seem like a bad idea - why add another competing standard instead of using one that exists?
In this section, we'll discuss some existing

## JSON-Schema

Really well-documented.
Various implementations exist.
Does not support RDF.
All information is scoped to a schema, which means properties are not re-usable.
In Atomic Data, we have both Properties and Classes, both of which have their own responsibilities in the schema.
The Properties dictate the `datatype`, `name` and `description`, and the Classes communicate which properties are `required` or `recommended`.
Like Atomic Schema, it can be described in JSON.

## SHACL

SHACL (Shape Constraint Language) is an RDF ontology that provides.
Like Atomic Schema, it can be described in RDF.

## ShEx

[ShEx](https://shex.io/) (Shape Expressions) is a standard for describing RDF graph constraints.
It introduces its own serialization format, called [ShExC](https://github.com/shexSpec/grammar/blob/master/ShExDoc.g4) (Shape Expressions Compact Syntax), which looks like this:

```ShExC
PREFIX school: <http://school.example/#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
PREFIX ex: <http://ex.example/#>

# Node constraint
school:enrolleeAge xsd:integer MinInclusive 13 MaxInclusive 20


school:Enrollee {
  # Triple constraint (including node constraint IRI)
  ex:hasGuardian IRI {1,2}
}
```

## OWL

OWL (the Web Ontology Language) is an ontology for ontologies: it can be used to create descriptions of how concepts in the world relate to each other.
OWL can also be used for _reasoning_, which deduces new information from existing information.
This means: adding new triples, based on the existing ones.
For example, if you know that `John` is a `Human`, and `Humans` are `Organisms`, you can deduce that `John` is an `Organism`.

However, OWL is not used for _constraining_ or _validating_ data.
Reasoners should not be used for checking if some piece is valid data, but only to create new data - it is always assumed that the input data is correct.
