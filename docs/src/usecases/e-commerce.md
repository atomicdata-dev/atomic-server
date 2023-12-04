{{#title Atomic Data for e-commerce & marketplaces}}
# Atomic Data for e-commerce & marketplaces

Buying good and services on the internet is currently responsible for about 15% of all commerce, and is steadily climbing.
The internet makes it easier to find products, compare prices, get information and reviews, and finally order something.
But the current e-commerce situation is far from perfect, as large corporations tend to monopolize, which means that we have less competition which ultimately harms prices and quality for consumers.
Atomic Data can help empower smaller businesses, make searching for specific things way easier and ultimately make things cheaper for everyone.

## Decentralize platform / sharing economy service marketplaces

Platforms like Uber, AirBNB and SnapCar are virtual marketplaces that help people share and find services.
These platforms are responsible for:

1. providing an interface for **managing offers** (e.g. describe your car, add specifications and pricing)
2. **hosting** the data of the offers themselves (make the data available on the internet)
3. providing a **search interface** (which means indexing the data from all the existing offers)
4. facilitating the **transaction** / payments
5. provide **trust** through reviews and warranties (e.g. refunds if the seller fails to deliver)

The fact that these responsibilities are almost always combined in a single platforms leads to vendor lock-in and an uncompetitive landscape, which ultimately harms consumers.
Currently, if you want to manage your listing / offer on various platforms, you need to manually adjust it on all these various platforms.
Some companies even prohibit offering on multiple platforms (which is a legal problem, not a technical one).
This means that the biggest (most known) platforms have the most listings, so if you're looking for a house / car / rental / meal, you're likely to go for the biggest business - because that's the one that has the biggest assortment.

Compare this to how the web works: every browser should support every type of webpage, and it does not matter where the webpage is hosted.
I can browse a webpage written on a mac on my windows machine, and I can read a webpage hosted by amazon on an google device.
It does not matter, because the web is _standardized_ and _open_, instead of being _centralized_ and managed by one single company as _proprietary_ data.
This openness of the web means that we get search engines like Google and Bing that _scrape_ the web and add it to their index.
This results in a dynamic where those who want to sell their stuff will need to share their stuff using an open standard (for webpages things like HTML and sometimes a bit of metadata), so crawlers can properly index the webpages.
We could do the same thing for _structured data_ instead of _pages_, and that's what Atomic Data is all about.

Let's discuss a more practical example of what this could mean.
Consider a restaurant owner who currently uses UberEats as their delivery platform.
Using Atomic Data, they could define their menu on their own website.
The Atomic Schema specification makes it easy to standardize how the data of a menu item looks like (e.g. price, image, title, allergens, vegan...).
Several platforms (potentially modern variants of platforms like JustEat / UberEats) could then crawl this standardized Atomic Data, index it, and make it easily searchable.
The customer would use one (or multiple) of these platforms, that would probably have the _exact same_ offers.
Where these platforms might differ, is in their own service offering, such as delivery speed or price.
This would result in a more competitive and free market, where customers would be able to pick a platform based on their service price and quality, instead of their list of offerings.
It would empower the small business owner to be far more flexible in which service they will do business with.

## Highly personalized and customizable search

Searching for products on the internet is mostly limited to text search.
If we want to buy a jacket, we see tonnes of jackets that are not even available in our own size.
Every single website has their own way of searching and filtering.

Imagine making a search query in _one_ application, and sending that to _multiple suppliers_, after you'll receive a fully personalized and optimized list of products.
Browsing in an application that you like to use, not bound to any one specific store, that doesn't track you, and doesn't show advertisements.
It is a tool that helps you to find what you need, and it is the job of producers to accurately describe their products in a format that your product browser can understand.

How do we get there?

Well, for starters, producers and suppliers will need to reach a consensus on _how to describe their articles_.
This is not new; for many products, we already have a common language.
Shoes have a shoe size, televisions have a screen size in diagonal inches, brightness is measured in nits, etc.
Describing this in a machine-readable and predictable format as data is the next logical step.
This is, of course, where Atomic Schema could help.
Atomic-server could be the connected, open source database that suppliers use to describe their products as data.

Then we'll also need to build a search interface that performs federated queries, and product-dependent filter options.

## Product lifecycle & supply chain insights

Imagine buying a product, and being able to see where each part came from.
The car that you buy might contain a list of all the maintenance moments, and every replaced part.
The raw materials used could be traced back to their origins.

This requires a high degree of coordination from each step in the supply chain.
This is exactly where Atomic Data shines, though, as it provides a highly standardized way of structuring, querying, authenticating an authorizing data.

Before we get to this point, we'll need to:

- Describe domain-specific product Classes using Atomic Schema, and their Properties.

## Product specific updates after purchase

Imagine buying an external battery pack with a production error.
All units with a serial number between 1561168 and 1561468 have a serious error, where overcharging could lead to spontaneous combustion.
This is something that you'd like to know.
But how would the _manufacturer_ of that resource know where to find you?
Well, if your Atomic Server would have a list of all the things that you've bought, it could _automatically_ subscribe to safety updates from all manufacturers.
When any of these manufacturers would publish a safety warning about a product that you possess, you'll get an alert.

Before we have this, well need to:

- Build notifications support (see [issue](https://github.com/atomicdata-dev/atomic-server/issues/77))
