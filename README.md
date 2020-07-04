# Atomicli

```sh
# Add a mapping, and store the Atomic Class locally
atomicli map person https://example.com/person
# Create a new instance with that Class
atomicli new person
name (required): John McLovin
age: 31
Created at: ipfs:Qwhp2fh3o8hfo8w7fhwo77w38ohw3o78fhw3ho78w3o837ho8fwh8o7fh37ho
# link to an Atomic Server where you can upload your stuff
# If you don't, your data exists locally and gets published to IPFS
atomicli setup
# install ontologies and their shortnames
atomicli install https://atomicdata.dev/ontologies/meetings
# when no URL is given, use the Ontola repo's ontologies
atomicli install meetings


```
