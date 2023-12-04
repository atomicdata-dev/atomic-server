# Atomic Runtime

_Status: not even ready to be part of the public docs_

Atomic Runtime offers a standardized way to bring algorithms to the data.
This enables privacy-friendly analysis, where the analyzed data stays at the source and only the results of some algoritm are sent back.

This is especially useful in research, where some data owners do not want to share their data with researches.
Sharing confidential / privacy / sensitive data is inherently risky, so it is understandable that data owners might not want to share this.
From the data owner perspective, it is safer to run any analysis locally, and send back the result to the researcher.
This is what the Atomic Runtime allows for.

## Atomic Runtime Interface

This is standardized set of query options that allow for fetching data from an Atomic Store.
It uses the WASI (WebAssmemly Systems Interface) (TODO)

## Creating an Analysis

- The Researcher writes code that interfaces on ART.
- The Researcher issues an AnalysisRequest on the server of the Data Owner.
- in a sandboxed environment which gives access to the data.

## Inspiration

- Freek Dijkstra / SurfSare (implemented a similar python based solution)
