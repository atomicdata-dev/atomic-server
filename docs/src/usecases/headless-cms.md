# Using Atomic-Server as an open source headless CMS

## Why people are switching to Headless CMS

Traditionally, content management systems were responsible for both managing the content as well as producing the actual HTML views that the user saw.
This approach has some issues regarding performance and flexibility that headless CMS tools solve.

- **Great performance**. We want pages to load in milliseconds, not seconds. Headless CMS tools + JAMSTACK style architectures are designed to give both performant initial page loads, as well as consecutive / dynamic loads.
- **High flexibility**. Designs change, and front-end developers want to use the tools that they know and love to create these designs effectively. With a headless CMS, you can build the front-end with the tools that you want, and make it look exactly like you want.
- **Easier content management**. Not every CMS is as fun and easy to use, as an admin, as others. Headless CMS tools focus on the admin side of things, so the front-end devs don't have to work on the back-end as well.

## Atomic Server

The [Atomic-Server](https://github.com/atomicdata-dev/atomic-server/blob/master/server/README.md) project may be the right choice for you if you're looking for a Headless CMS:

<!-- List copied from https://github.com/atomicdata-dev/atomic-server/blob/master/README.md -->
- **Free and open source**. MIT licensed, no strings attached.
- **Easy to use API**. Atomic-Server is built using the [Atomic Data specification](../atomic-data-overview.md). It is well-documented, and uses conventions that most web developers are already familiar with.
- **Typescript & React libraries**. Use the existing react hooks to make your own fully editable, live-reloaded web application.
- **Fast**. 1ms responses on my laptop. It's written in Rust, so it squeezes out every cycle of your server.
- **Lightweight**. It's a single 8MB binary, no external dependencies needed.
- **Easy to setup**. Just run the binary and open the address. Even HTTPS support is built-in.
- **Clean, powerful admin GUI**. The Atomic-Data-Browser front-end gives you a very easy interface to manage your content.
- **Share your data models**. Atomic Data is designed to achieve a more decentralized web. You can easily re-use existing data models, or share the ones you built.
- **Files / Attachments**. Upload and preview files.
- **Pagination / sorting / filtering**. Query your data.
- **Versioning**. Built-in history, where each transaction is saved.
- **Websockets**. If you need live updates and highly interactive apps (collaborative documents and chatrooms), we've got your back.
- **Full-text search**. No need for a big elasticsearch server - atomic-server has one built-in.

## Limitations

- No support for image resizing, [as of now](https://github.com/atomicdata-dev/atomic-server/issues/257)
- No GraphQL support [(see issue)](https://github.com/atomicdata-dev/atomic-server/issues/251)

## Setting up the server

- One-liners: `cargo install atomic-server` or `docker run -p 80:80 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`
- Check out the [readme!](https://github.com/atomicdata-dev/atomic-server)

## Using the data in your (React / NextJS) app

The `@tomic/lib` and `@tomic/react` typescript NPM libraries can be used in any JS project.

In the next section, we'll discuss how to use Atomic-Server in your React project.

## Compared to alternative open source headless CMS software

- **Strapi**: Atomic-Server doesn't need an external database, is easier to setup, has live synchronization support and is way faster. However, Strapi has a plugin system, is more polished, and has GraphQL support.
- **
