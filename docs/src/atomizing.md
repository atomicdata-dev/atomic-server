# Atomizing: How to create and publish Atomic Data

Now that we're familiar with the basics of Atomic Data Core and its Schema, it's time to create some Atomic Data!
We call the process of turning data into Atomic Data _Atomizing_.
During this process, we **upgrade the data quality**.
Our information becomes more valuable.
Let's summarize what the advantages are:

- Your data becomes **available on the web** (publicly, if you want it to)
- It can now **link to other data**, an become part of a bigger web of data
- It becomes **strictly typed**, so developers can easily and safely re-use it in their software
- It becomes **easier to understand**, because people can look at the Properties and see what they mean
- It can be **easily converted** into many formats (JSON, Turtle, CSV, XML, more...)

## Three ways to Atomize data

In general, there are three ways to create Atomic Data:

- [Using the **Atomic-Server** app + GUI](./atomic-server.md) (easy, only for direct user input)
- [Create an **importable JSON-AD file**](./create-json-ad.md) (medium, useful if you want to convert existing data)
- [Make your existing service / app **host and serialize Atomic Data**](./interoperability/upgrade.md) (hard, if you want to make your entire app be part of the Atomic Web!)
