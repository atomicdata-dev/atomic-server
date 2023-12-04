{{#title Atomic Commits: Concepts}}
# Atomic Commits: Concepts

## Commit

_url: [https://atomicdata.dev/classes/Commit](https://atomicdata.dev/classes/Commit)_

A Commit is a Resource that describes how a Resource must be updated.
It can be used for auditing, versioning and feeds.
It is cryptographically signed by an [Agent](https://atomicdata.dev/classes/Agent).

The **required fields** are:

- `subject` - The thing being changed. A Resource Subject URL (HTTP identifier) that the Commit is changing about. A Commit Subject must not contain query parameters, as these are reserved for dynamic resources.
- `signer` - Who's making the change. The Atomic URL of the Author's profile - which in turn must contain a `publicKey`.
- `signature` - Cryptographic proof of the change. A hash of the JSON-AD serialized Commit (without the `signature` field), signed by the Agent's `private-key`. This proves that the author is indeed the one who created this exact commit. The signature of the Commit is also used as the identifier of the commit.
- `created-at` - When the change was made. A UNIX timestamp number of when the commit was created.

The **optional method fields** describe how the data must be changed:

- `destroy` - If true, the existing Resource will be removed.
- `remove` - an array of Properties that need to be removed (including their values).
- `set` - a Nested Resource which contains all the new or edited fields.
- `push` - a Nested Resource which contains all the fields that are _appended_ to. This means adding items to a new or existing ResourceArray.

These commands are executed in the order above.
This means that you can set `destroy` to `true` and include `set`, which empties the existing resource and sets new values.

### Posting commits using HTTP

Since Commits contains cryptographic proof of authorship, they can be accepted at a public endpoint.
There is no need for authentication.

A commit should be sent (using an HTTPS POST request) to a `/commmit` endpoint of an Atomic Server.
The server then checks the signature and the author rights, and responds with a `2xx` status code if it succeeded, or an `5xx` error if something went wrong.
The error will be a JSON object.

### Serialization with JSON-AD

Let's look at an example Commit:

```json
{
  "@id": "https://atomicdata.dev/commits/3n+U/3OvymF86Ha6S9MQZtRVIQAAL0rv9ZQpjViht4emjnqKxj4wByiO9RhfL+qwoxTg0FMwKQsNg6d0QU7pAw==",
  "https://atomicdata.dev/properties/createdAt": 1611489929370,
  "https://atomicdata.dev/properties/isA": [
    "https://atomicdata.dev/classes/Commit"
  ],
  "https://atomicdata.dev/properties/set": {
    "https://atomicdata.dev/properties/shortname": "1611489928"
  },
  "https://atomicdata.dev/properties/signature": "3n+U/3OvymF86Ha6S9MQZtRVIQAAL0rv9ZQpjViht4emjnqKxj4wByiO9RhfL+qwoxTg0FMwKQsNg6d0QU7pAw==",
  "https://atomicdata.dev/properties/signer": "https://surfy.ddns.net/agents/9YCs7htDdF4yBAiA4HuHgjsafg+xZIrtZNELz4msCmc=",
  "https://atomicdata.dev/properties/previousCommit": "https://surfy.ddns.net/commits/9YCs7htDdF4yBAiA4HuHgjsafg+xZIrtZNELz4msCmc=",
  "https://atomicdata.dev/properties/subject": "https://atomicdata.dev/test"
}
```

This Commit can be sent to any Atomic Server.
This server, in turn, should verify the signature and the author's rights before the server applies the Commit.

### Calculating the signature

The signature is a base64 encoded Ed25519 signature of the deterministically serialized Commit.
Calculating the signature is a delicate process that should be followed to the letter - even a single character in the wrong place will result in an incorrect signature, which makes the Commit invalid.

The first step is **serializing the commit deterministically**.
This means that the process will always end in the exact same string.

- Serialize the Commit as JSON-AD.
- Do not serialize the signature field.
- Do not include empty objects or arrays.
- If `destroy` is false, do not include it.
- All keys are sorted alphabetically - both in the root object, as in any nested objects.
- The JSON-AD is minified: no newlines, no spaces.

This will result in a string.
The next step is to sign this string using the Ed25519 private key from the Author.
This signature is a byte array, which should be encoded in base64 for serialization.
Make sure that the Author's URL resolves to a Resource that contains the linked public key.

Congratulations, you've just created a valid Commit!

Here are currently working implementations of this process, including serialization and signing (links are permalinks).

- [in Rust (atomic-lib)](https://github.com/atomicdata-dev/atomic-server/blob/ceb88c1ae58811f2a9e6bacb7eaa39a2a7aa1513/lib/src/commit.rs#L81).
- [in Typescript / Javascript (atomic-data-browser)](https://github.com/atomicdata-dev/atomic-data-browser/blob/fc899bb2cf54bdff593ee6b4debf52e20a85619e/src/atomic-lib/commit.ts#L51).

If you want validate your implementation, check out the tests for these two projects.

### Applying the Commit

If you're on the receiving end of a Commit (e.g. if you're writing a server or a client who has to parse Commits), you will _apply_ the Commit to your Store.
If you have to _persist_ the Commit, you must perform all of the checks.
If you're writing a client, and you trust the source of the Commit, you can probably skip the validation steps.

Here's how you apply a Commit:

1. Check if the Subject URL is valid
2. Validate the signature. This means serialize the Commit deterministically (see above), check the Agent's publickey (you might need to fetch this one), verify if the signature matches.
3. Check if the timestamp matches is OK. I think an acceptable window is 10 seconds.
4. If the Commit is for an existing resource, get it.
5. Validate the Rights of the one making the Commit.
6. Check if the `previousCommit` of the Commit matches with the `previousCommit` of the Resource.
7. Iterate over the `set` fields. Overwrite existing, or add the new Values. Make sure the Datatypes match with the respective Properties.
8. Iterate over the `remove` fields. Remove existing properties.
9. If the Resource has one or more classes, check if the required Properties are there.
10. You might want to perform some custom validations now (e.g. if you accept an Invite, you should make sure that the one creating the Invite has the correct rights to actually make it!)
11. Store the created Commit as a Resource, and store the modified Resource!

## Limitations

- Commits adjust **only one Resource at a time**, which means that you cannot change multiple in one commit. ([issue](https://github.com/atomicdata-dev/atomic-data-docs/issues/130))
- The one creating the Commit will **need to sign it**, which may make clients that write data more complicated than you'd like. You can also let Servers write Commits, but this makes them less verifiable / decentralized.
- Commits require signatures, which means **key management**. Doing this securely is no trivial matter.
- The signatures **require JSON-AD** serialization
- If your implementation persists all Commits, you might need to **store a lot of data**.
