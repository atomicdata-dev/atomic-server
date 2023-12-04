{{#title How does Atomic Data relate to IPFS?}}
# Atomic Data and IPFS

## What is IPFS

IPFS (the InterPlanetary File System) is a standard that enables decentralized file storage and retrieval using content-based identifiers.
Instead of using an HTTP URL like `http://example.com/helloworld`, it uses the IPFS scheme, such as `ipfs:QmX6j9DHcPhgBcBtZsuRkfmk2v7G5mzb11vU9ve9i8vDsL`.
IPFS identifies things based on their unique content hash (the long, seemingly random string) using a thing called a Merkle DAG ([this great article](https://medium.com/textileio/whats-really-happening-when-you-add-a-file-to-ipfs-ae3b8b5e4b0f#:~:text=In%20practice%2C%20content%20addressing%20systems,function%2C%20to%20produce%20a%20digest.&text=From%20raw%20image%20to%20cryptographic%20digest%20to%20content%20id%20(multihash).) explains it nicely).
This is called a [CID](https://github.com/multiformats/cid), or Content ID.
This simple idea (plus some not so simple network protocols) allows for decentralized, temper-proof storage of data.
This fixes some issues with HTTP that are related to its centralized philosophy: **no more 404s**!

## Why is IPFS interesting for Atomic Data

Atomic Data is highly dependent on the availability of Resources, especially Properties and Datatypes.
These resources are meant to be re-used a lot, and when these go offline or change (for whatever reason), it could cause issues and confusion.
IPFS guarantees that these resources are entirely static, which means that they cannot change.
This is useful when dealing with Properties, as a change in datatype could break things.
IPFS also allows for location-independent fetching, which means that resources can be retrieved from any location, as long as it's online.
This Peer-to-peer functionality is a very fundamental advantage of IPFS over HTTP, especially when the resources are very likely to be re-use, which is _especially_ the case for Atomic Data Properties.

## Considerations using IPFS URLs

IPFS URLs are **static**, which means that their contents can never change.
This is great for some types of data, but not so much for others.
If you're describing a time-dependent thing (such as a person's job), you'll probably want to know what the _current_ value is, and that is not possible when you only have an IPFS identifier.
This can be fixed by including an HTTP URL in IPFS bodies.

IPFS data is also **hard to remove**, as it tends to be replicated across machines.
If you're describing personal, private information, it can therefore be a bad idea to use IPFS.

And finally, its **performance** is typically not as good as HTTP.
If you know the IPFS gateway that hosts the IPFS resource that you're looking for, things improve drastically.
Luckily for Atomic Data, this is often the case, as we know the HTTP url of the server and could try whether that server has an IPFS gateway.

## Atomic Data and IPLD

IPLD (not IPFS) stands for InterPlanetary Linked Data, but is not related to RDF.
The scope seems fundamentally different from RDF, too, but I have to read more about this.

## Share your thoughts

Discuss on [this issue](https://github.com/ontola/atomic-data-docs/issues/42).
