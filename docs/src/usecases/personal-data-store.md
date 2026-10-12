{{#title Atomic Data for personal data stores}}
# Atomic Data for personal data stores

A Personal Data Store (or personal data service) is a place where you store all sorts of personal information.
For example a list of contacts, todo items, pictures, or your profile data.
Not that long ago, the default for this was the `my Documents` folder on your hard drive.
But as web applications became better, we started moving our data to the cloud.
More and more of our personal information is stored by large corporations who use the information to build profiles to show us ads.
And as cloud consumers, we often don't have the luxury of moving our personal data to a place to where we want it to be.
Many services don't even provide export functionality, and even if they do, the exports often lack information or are not interoperable with other apps.

Atomic Data re-introduces data ownership.
Because the specification helps to standardize information, it becomes easier to make data interoperable.
And even more important: apps don't need their own back-end. They can use the same personal data store.

That store is no longer a server you have to run.
In the [local-first](../local-first.md) model your personal data store is the device in your hand: an encrypted database owned by your key, with every edit signed by you.
An always-on [AtomicServer](../atomic-server.md), self-hosted or run for you on [atomic.place](https://atomic.place), is a replica of it that stays reachable while your devices sleep and that a browser can talk to.
Any number of apps, on any of your devices, read and write the same Drives and [sync](../sync.md) with each other.

What still needs work is the developer side: tutorials, published SDKs for every platform, and the ecosystem of apps that makes a shared personal store worth having.
