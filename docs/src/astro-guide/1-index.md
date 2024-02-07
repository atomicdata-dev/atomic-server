# Creating a portfolio website using Astro and Atomic Server

Atomic Server is a great fit for a headless CMS because it works seamlessly on the server and client while providing a top notch developer experience.
In this Guide we will build a portfolio site using [Astro](https://astro.build/) to serve and build our pages and use Atomic Data to hold our data.

Astro is a web framework for creating fast multi page applications using web technology.
It plays very nicely with Atomics client library `@tomic/lib`.

There are a few things that won't be covered in this guide like styling and CSS.
There will be very minimal use of CSS in this guide so we can focus on the technical parts of the website.
Feel free to spice it up and add some styling while following along though.

I will also not cover every little detail about Astro, only what is necessary to follow along with this guide.
If you're completely new to Astro consider skimming the [documentation](https://docs.astro.build/en/getting-started/) to see what it has to offer.

With all that out of the way lets start by setting up your atomic data server. If you already have a server running skip to [Creating the frontend](3-frontend-setup.md)
