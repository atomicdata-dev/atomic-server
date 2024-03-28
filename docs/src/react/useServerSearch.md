# useServerSearch

AtomicServer has a very powerful full-text search feature and Atomic React makes it super easy to use.
The `useServerSearch` hook takes a search query and optionally additional filters and returns a list of results.

Here we build a component that renders a search input and shows a list of results as you type.

```jsx
import { useState } from 'react';
import { useResource, useServerSearch } from '@tomic/react';

export const Search = () => {
  const [inputValue, setInputValue] = useState('');
  const { results } = useServerSearch(inputValue);

  return (
    <search>
      <input
        type='search'
        placeholder='Search...'
        value={inputValue}
        onChange={e => setInputValue(e.target.value)}
      />
      <ol>
        {results.map(result => (
          <SearchResultItem key={result} subject={result} />
        ))}
      </ol>
    </search>
  );
};

interface SearchResultItemProps {
  subject: string;
}

const SearchResultItem = ({ subject }: SearchResultItemProps) => {
  const resource = useResource(subject);

  return <li>{resource.title}</li>;
};
```

## Reference

### Parameters

- `query: string` - The search query.
- `options?: Object` - Additional search parameters

Options:
| Name | Type | Description |
| ---- | ---- | ----------- |
| `debounce` | number | Amount of milliseconds the search should be debounced (default: 50). |
| `allowEmptyQuery` | boolean | If you set additional filters your search might get results back even when the query is still empty. If you want this you can enable this setting (default: false). |
| `include` | boolean | If true sends full resources in the response instead of just the subjects |
| `limit` | number | The max number of results to return (default: 30).|
| `parents` | string[] | Only include resources that have these given parents somewhere as an ancestor |
| `filters` | Record<string, string> | Only include resources that have matching values for the given properties. Should be an object with subjects of properties as keys |

### Returns

Returns an object with the following fields:

- `results: string[]` - An array with the subjects of resources that match the search query.
- `loading: boolean` - Whether the search is still loading.
- `error: Error | undefined` - If an error occurred during the search, it will be stored here.
