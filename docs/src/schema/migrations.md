# Migrations and API versioning in Atomic Data

_Status: design / concept stage_

Models are rarely static.
As new insights and business requirements influence our internal understanding of some domain, we often make changes to a model.
That's why Atomic Classes have the optional `deprecatedProperties` Property, which helps to communicate if properties are changed in some newer version.

For example, we might start off with a `Person => employer => Organization` relationship.
Later, we might need some way to describe the Role of that person, and when the employment will end.
To solve this, the `employer` relation might be expanded into a separate Resource, with a set of props (e.g. `role` and `startedAt`).

Now, in many RESTful APIs, versioning is done by adding an endpoint such as `/api/v2`.
Every versioned endpoint has differences, and their own documentation deprecation.
However, this means that links made to _API versioned_ resources (`v1/somePerson`) should be updated (`v2/somePerson)`.
This is not a good approach for linked data.

Instead of _replacing_ the relationship, we recommend to simply _add a new Property_, and keeping the old one for some time.
We might add a `Employment` Class, and give it `role`, `employee`, `organization` and `startedAt` properties.
The relationship might look like this: `Person => employment => Employment => organization => Organization`.
We now have _two_ places where we can find what the employer of a person is - the `employer` property, but also `employment`.
Maintaining both might make sense, but is probably not necessary and only confusing.
The API should communicate that the `employment` Property is the one that will be maintained, and the `employer` will be removed.

The `employer` relationship should be added to `deprecatedProperties` in the  `Person` class.
