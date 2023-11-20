# @tomic/svelte

An implementation of Atomic Data for [Svelte](https://svelte.dev/).
This library is still at an early stage and the API is subject to change.

[See open source example project built with @tomic/svelte.](https://github.com/ontola/wonenatthepark)

## Quick Examples

### Getting a resource and displaying one of its properties

```html
<script lang="ts">
  import { getResource, getValue } from '@tomic/svelte';
  import { Core } from '@tomic/lib';

  const resource = getResource<Core.Agent>('https://example.com/user1');
</script>

<h1>{$resource.props.name}</h1>
```

### Changing the value of a property with an input field

```html
<script lang="ts">
  import { getResource, getValue, setValue } from '@tomic/svelte';
  import { core, Core } from '@tomic/lib';

  const resource = getResource<Core.Agent>('https://example.com/user1');
  const name = getValue(resource, core.properties.name); // Writable<string>
</script>

<input bind:value="{$name}" />
```

## Getting started

Install the library with your preferred package manager:

```sh
npm install -S @tomic/svelte @tomic/lib
```

```sh
yarn add @tomic/svelte @tomic/lib
```

```sh
pnpm add @tomic/svelte @tomic/lib
```

Initialise the store

```html
// App.svelte

<script lang="ts">
  import { initStore } from '@tomic/svelte';
  import { Store } from '@tomic/lib';

  onMount(() => {
    // This is where you configure your atomic data store.
    const store = new Store();
    initStore(store);
  });
</script>

// do sveltey things
```

You can now access this store from any component in your app with the store store.

```svelte
// Some random component.svelte

<script lang="ts">
  import { store } from '@tomic/svelte';

  const resource = $store.getResourceLoading('https://atomicdata.dev/documents/tgzamh5hk2t');
</script>
```

However, this resource does not update when some of its data changes somewhere else in your app.
That's where the `getResource` and `getValue` functions come in handy.

To get a value and display it in your component we first retrieve (or create) a resource from the store with `getResource` and then get its value with `getValue`.

```html
// Some random component.svelte

<script lang="ts">
  import { getResource, getValue } from '@tomic/svelte';
  import { core } from '@tomic/lib';

  const resource = getResource('https://example.com/');
  const name = getValue(resource, core.properties.name);
</script>

<main>
  <h1>{$name}</h1>
  ...
</main>
```

Updating the values of a resource is super simple, just do what you would normally do with a writable svelte store:

```ts
const value = getValue(resource, core.properties.name);

$value = 'New Value';
```

The value now updates and changes will permeate through the store.

## Typescript

This library is build using typescript and is fully typed. To full advantage of Atomic Data's strong type system use [@tomic/cli](https://www.npmjs.com/package/@tomic/cli) to generate types using Ontologies. These can then be used like this:

```html
<script lang="ts">
  import { getResource, getValue } from '@tomic/svelte';
  import { core } from '@tomic/lib';
  // User 'app' ontology generated using @tomic/cli
  import { Person, app } from './ontologies';

  const resource = getResource<Person>('https://myapp.com/users/me'); // Readable<Resource<Person>>
  const name = getValue(resource, core.properties.name); // Writable<string>
  const hobbies = getValue(resource, app.properties.hobbies); // Writable<string[]>
</script>

<main>
  <h1>{$name}</h1>
  ...
</main>
```
