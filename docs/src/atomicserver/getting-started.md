# Creating Atomic Data using Atomic-Server

Here is everything you need to get started:

- [Running Atomic-Server locally (optional)](#running-atomic-server-locally-optional)
- [There's more!](#theres-more)

## Running Atomic-Server locally (optional)

In this guide, we can simply use `atomicdata.dev` in our browser without installing anything.
So you can skip this step and go to _Creating your first Atomic Data_.
But if you want to, you can run Atomic-Server on your machine in a couple of ways:

- **Using Docker** is probably the quickest: `docker run -p 80:80 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`.
- **Using a binary**: download a binary release from the [`releases`](https://github.com/atomicdata-dev/atomic-server/releases) page and open it using a terminal.
- **Using Cargo**: `cargo install atomic-server` and then run `atomic-server` to start.

_[The Setup page](/atomicserver/setup) contains more (and up-to-date) information about how to use it!_

## There's more!

This was just a very brief introduction to Atomic Server, and its features.
There's quite a bit that we didn't dive in to, such as versioning, file uploads, the collaborative document editor and more...
But by clicking around you're likely to discover these features for yourself.

In the next page, we'll dive into how you can create an publish JSON-AD files.
