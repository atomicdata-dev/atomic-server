{{#title When (not) to use Atomic Data}}
# When (not) to use Atomic Data

## When should you use Atomic Data

- **Flexible schemas**. When dealing with structured wikis or semantic data, various instances of things will have different attributes. Atomic Data allows _any_ kind of property on _any_ resource.
- **Open data**. Atomic Data is a bit harder to create than plain JSON, for example, but it is easier to re-use and understand. It's use of URLs for properties makes data self-documenting.
- **High interoperability requirements**. When multiple groups of people have to use the same schema, Atomic Data provides easy ways to constrain and validate the data and ensure type safety.
- **Connected / decentralized data**. With Atomic Data, you use URLs to point to things on other computers. This makes it possible to connect datasets very explicitly, without creating copies. Very useful for decentralized social networks, for example.
- **Auditability & Versioning**. Using Atomic Commits, we can store all changes to data as transactions that can be replayed. This creates a complete audit log and history.
- **JSON or RDF as Output**. Atomic Data serializes to idiomatic, clean JSON as well as various RDF formats (Turtle / JSON-LD / n-triples / RDF/XML).

## When not to use Atomic Data

- **Internal use only**. If you're not sharing structured data, Atomic Data will probably only make things harder for you.
- **Big Data**. If you're dealing with TeraBytes of data, you probably don't want to use Atomic Data. The added cost of schema validation and the lack of distributed / large scale persistence tooling makes it not the right choice.
- **Video / Audio / 3D**. These should have unique, optimized binary representations and have very strict, static schemas. The advantages of atomic / linked data do little to improve this, unless it's just for metadata.
