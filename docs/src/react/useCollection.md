# useCollection

The useCollection hook is used to fetch a [Collection](../js-lib/collection.md).
It returns the collection together with a function to invalidate and re-fetch it.

```typescript
// Create a collection of all agents on the drive.
const { collection ,invalidateCollection } = useCollection({
  property: core.properties.isA,
  value: core.classes.Agent
});
```

## Reference

### Parameters

- **query**: [QueryFilter](#queryfilter) - The query used to build the collection
- **options**: [UseCollectionOptions?](#usecollectionoptions) - An options object described below.


### Returns

Returns an object containing the following items:

- **collection**: [Collection](../js-lib/collection.md) - The collection.
- **invalidateCollection**: `() => void` - A function to invalidate and re-fetch the collection.

### QueryFilter

A QueryFilter is an object with the following properties:

| Name | Type | Description |
| --- | --- | --- |
| property | `string?` | The subject of the property you want to filter by. |
| value | `string?` | The value of the property you want to filter by. |
| sort_by | `string?` | The subject of the property you want to sort by. By default collections are sorted by subject |
| sort_desc | `boolean?` | If true, the collection will be sorted in descending order. (Default: false) |

### UseCollectionOptions
| Name | Type | Description |
| --- | --- | --- |
| pageSize | `number?` | The max number of members per page. Defaults to 30 |
| server | `string?` | The server that this collection should query. Defaults to the store's serverURL |

## Additional Hooks

Working with collections in React can be a bit tedious because most methods of `Collection` are asynchronous.
Luckily, we made some extra hooks to help with the most common patterns.

### useCollectionPage

The `useCollectionPage` hook makes it easy to create paginated views. It takes a collection and a page number and returns the items on that page.

```jsx
import {
  core,
  useCollection,
  useCollectionPage,
  useResource,
} from '@tomic/react';
import { useState } from 'react';

interface PaginatedChildrenProps {
  subject: string;
}

export const PaginatedChildren = ({ subject }: PaginatedChildrenProps) => {
  const [currentPage, setCurrentPage] = useState(0);

  const { collection } = useCollection({
    property: core.properties.parent,
    value: subject,
  });

  const items = useCollectionPage(collection, currentPage);

  return (
    <div>
      <button onClick={() => setCurrentPage(p => Math.max(0, p - 1))}>
        Prev
      </button>
      <button
        onClick={() =>
          setCurrentPage(p => Math.min(p + 1, collection.totalPages - 1))
        }
      >
        Next
      </button>
      {items.map(item => (
        <Item key={item} subject={item} />
      ))}
    </div>
  );
};

const Item = ({ subject }: { subject: string }) => {
  const resource = useResource(subject);

  return <div>{resource.title}</div>;
};
```

### UseMemberOfCollection

Building virtualized lists is always difficult when working with unfamiliar data structures, especially when the data is paginated.
The `UseMemberOfCollection` hook makes it easy.

It takes a collection and index and returns the resource at that index.

In this example, we use the [`react-window`](https://github.com/bvaughn/react-window?tab=readme-ov-file) library to render a virtualized list of comments.

```jsx
import { useCallback } from 'react';
import { FixedSizeList } from 'react-window';
import Autosizer from 'react-virtualized-auto-sizer';
import { useCollection, useMemberOfCollection } from '@tomic/react';
import { myOntology, type Comment } from './ontologies/myOntology';

const ListView = () => {
  // We create a collection of all comments.
  const { collection } = useCollection({
    property: core.properties.isA,
    value: myOntology.classes.comment,
  });

  // We have to define the CommentComponent inside the ListView component because it needs access to the collection.
  // Normally you'd pass it as a prop but that is not possible due to how react-window works.
  const CommentComp = useCallback(({index}: {index: number}) => {
    // Get the resource at the specified index.
    const comment = useMemberOfCollection<Comment>(collection, index);

    return (
      <div>
        <UserInline subject={comment.props.writtenBy}>
        <p>{comment.props.description}</p>
      </div>
    );
  }, [collection]);

  return (
    <Autosizer>
    {({width, height}) => (
      <FixedSizeList
        height={height}
        itemCount={collection.totalMembers}
        itemSize={50}
        width={width}
      >
        {CommentComp}
      </FixedSizeList>
    )}
    </Autosizer>
  );
}
```
