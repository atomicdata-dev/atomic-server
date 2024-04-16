# useResource

`useResource` is the primary way to fetch data with Atomic React.
It returns a [Resource](../js-lib/resource.md) object, that is still loading when initially returned.
When the data is loaded, the component will re-render with the new data allowing you to show some UI before the content is available, resulting in a more responsive user experience.

The hook also subscribes to changes meaning that the component will update whenever the data changes clientside and **even serverside**.
You essentially get real-time features for free!

```jsx
import { useResource } from '@tomic/react';

export const Component = () => {
  const resource = useResource('https://my-atomic-server/my-resource');

  // Optionally show a loading state
  if (resource.loading) {
    return <Loader />
  }

  return (
    <p>{resource.title}</p>
  )
}
```

## Typescript

Just like the [`store.getResource`](../js-lib/resource.md#typescript) method, `useResource` can be annotated with a subject of a certain class.

```typescript
import { useResource } from '@tomic/react';
import type { Author } from './ontologies/blogsite' // <-- Generated with @tomic/cli

// ...
const resource = useResource<Author>('https://my-atomic-server/moderndayshakespear69')
const age = Date.now() - resource.props.yearOfBirth
```

## Reference

### Parameters

- **subject**: `string` - The subject of the resource you want to fetch.
- **options**: `FetchOpts` - (Optional) Options for how the store should fetch the resource.

**FetchOpts**:

| Name | Type | Description |
| --- | --- | --- |
| allowIncomplete | `boolean` | ? |
| noWebSocket | `boolean` | (Optional) If true, uses HTTP to fetch resources instead of websockets |
| newResource | `Resource` | (Optional) If true, will not send a request to a server, it will simply create a new local resource.|

### Returns

[Resource](../js-lib/resource.md) - The fetched resource (might still be in a loading state).

## Views

A common way to build interfaces with Atomic React is to make a *view* component.
Views are a concept where the component is responsible for rendering a resource in a certain way to fit in the context of the view type.

The view selects a component based on the resource's class or renders a default view when there is no component for that class.
In this example, we have a `ResourceInline` view that renders a resource inline in some text.
For most resources, it will just render the name but for a Person or Product, it will render a special component.

```jsx
// views/inline/ResourceInline.tsx

import { useResource } from '@tomic/react';
import { shop } from '../../ontologies/shop'; // <-- Generated with @tomic/cli
import { PersonInline } from './PersonInline';
import { ProductInline } from './ProductInline';

interface ResourceInlineProps {
  subject: string;
}

export interface ResourceInlineViewProps<T> {
  resource: Resource<T>;
}

export const ResourceInline = ({ subject }: ResourceInlineProps): JSX.Element => {
  const resource = useResource(subject);

  const Comp = resource.matchClass({
    [shop.classes.product]: ProductInline,
    [shop.classes.person]: PersonInline,
  }, Default);

  return <Comp subject={subject} />
}

const Default = ({ subject }: ResourceInlineViewProps<unknown>) => {
  const resource = useResource(subject);

  return <span>{resource.title}</span>
}
```

The `PersonInline` view will render a person resource inline.
It could render a mention-like thing with the person's name, their profile picture and a link to their profile for example.

```jsx
// views/inline/PersonInline.tsx
import { useResource, Resource, type Server } from '@tomic/react';
import type { Person } from '../../ontologies/social' // <-- Generated with @tomic/cli
import type { ResourceInlineViewProps } from './ResourceInline';

export const PersonInline = ({ resource }: ResourceInlineViewProps<Person>) => {
  const image = useResource<Server.File>(resource.props.image);

  return (
    <span className="person-inline">
      <img src={image.props.downloadUrl} className="profile-image-inline" />
      <span>{resource.title}</span>
    </span>
  )
}
```
