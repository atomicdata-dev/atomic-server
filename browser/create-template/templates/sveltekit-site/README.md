# sveltekit-site

A website build with [SvelteKit](https://kit.svelte.dev/) powered by [AtomicServer](https://github.com/atomicdata-dev/atomic-server)
Data is dynamically rendered based on the data present in AtomicServer.

## Architecture

Atomic Data resources are rendered by views.
These views are components that accept a resource as prop and render the data in a certain way.
For example the `BlogPostFullPage` view renders a `blog-post` resource as a full page.

Oftentimes these views also come with a kind of view selector component that determines what component to render based on the resources class.
An example of this would be `FullPageView`.

These selector components are great for when a resource can reference another resource without a classtype, meaning it can be any kind of resource.
For example, the `page` class has a `blocks` property that can reference any type of resource.
The FullPage view for the `page` class (`PageFullPage`) therefore renders a `BlockView` component that selects the appropriate component to render, i.e. a `TextBlock` or an `ImageGalleryBlock`.

## Updating the generated ontology.

After making changes to an ontology you need to re-generate them in your code. This can be done by running:

```bash
<PACKAGE_MANAGER_RUN> update-ontologies
```

## Developing

Once you've installed the dependencies and generated the ontologies with `<PACKAGE_MANAGER> install` and `<PACKAGE_MANAGER_RUN> update-ontologies`, start a development server:

```bash
<PACKAGE_MANAGER_RUN> dev

# or start the server and open the app in a new browser tab
<PACKAGE_MANAGER_RUN> dev -- --open
```

## Building

To create a production version of your app:

```bash
<PACKAGE_MANAGER_RUN> build
```

You can preview the production build with `<PACKAGE_MANAGER_RUN> preview`.

> To deploy your app, you may need to install an [adapter](https://kit.svelte.dev/docs/adapters) for your target environment.
