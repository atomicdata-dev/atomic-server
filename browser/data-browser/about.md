![Atomic Data](https://raw.githubusercontent.com/atomicdata-dev/atomic-server/master/docs/src/assets/atomic_data_logo_stroke.svg)

*The easiest way to **create**, **share** and **model** linked data.*

Atomic Data is a proposed standard for modeling and exchanging linked data. It uses links to connect pieces of data, and therefore makes it easier to connect datasets to each other, even when these datasets exist on separate machines. It aims to help realize a more decentralized internet that encourages data ownership and interoperability.

Atomic Data is especially suitable for knowledge graphs, distributed datasets, semantic data, p2p applications, decentralized apps, and data that is meant to be shared. It is designed to be highly extensible, easy to use, and to make the process of domain specific standardization as simple as possible. Check out **[the docs](https://docs.atomicdata.dev/)** for more information about Atomic Data.

About this app
--------------

You're looking at [atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser), an open-source client for viewing and editing data. Please add an issue if you encouter problems or have a feature request. Expect bugs and issues, because this stuff is pretty beta.

The back-end of this app is [atomic-server](https://github.com/atomicdata-dev/atomic-data-browser), which you can think of as an open source, web-native database.

Things to visit
---------------

-   [List of lists](https://atomicdata.dev/collections)
-   [List of Classes](https://atomicdata.dev/classes)
-   [List of Properties](https://atomicdata.dev/properties)

Run your own server
-------------------

The easiest way to run an [atomic-server](https://github.com/atomicdata-dev/atomic-data-browser) is by using Docker:

`docker run -p 80:80 -p 443:443 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`

...and visit [localhost](http://localhost).

Join the community
------------------

Atomic Data is open and fully powered by volunteers. We're looking for people who want to help discuss various design challenges and work on implmenentations. If you have any questions, or want to help out, feel free to join our [Discord](https://discord.gg/a72Rv2P).
Sign up to [our newsletter](https://docs.atomicdata.dev/newsletter.html) if you'd like to get updated.
