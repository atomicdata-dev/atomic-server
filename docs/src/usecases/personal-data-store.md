{{#title Atomic Data for personal data stores}}
# Atomic Data for personal data stores

A Personal Data Store (or personal data service) is a place where you store all sorts of personal information.
For example a list of contacts, todo items, pictures, or your profile data.
Not that long ago, the default for this was the `my Documents` folder on your hard drive.
But as web applications became better, we started moving our data to the cloud.
More and more of our personal information is stored by large corporations who use the information to build profiles to show us ads.
And as cloud consumers, we often don't have the luxury of moving our personal data to a place to where we want it to be.
Many services don't even provide export functionality, and even if they do, the exports often lack information or are not interoperable with other apps.

Atomic Data could help to re-introduce data ownership.
Because the specification helps to standardize information, it becomes easier to make data interoperable.
And even more important: Apps don't need their own back-end - they can use the same personal data store: an Atomic Server (such as [this one](https://github.com/atomicdata-dev/atomic-serverob/master/server/README.md)).

Realizing this goal requires quite a bit of work, though.
This specification needs to mature, and we need reliable implementations.
We also need proper tutorials, libraries and tools that convince developers to use atomic data to power their applications.
