# useCanWrite

`useCanWrite` is a hook that can be used to check if an agent has write access to a certain resource.

Normally you would just use `await resource.canWrite()` but since this is an async function, using it in react can be annoying.

The `useCanWrite` hook works practically the same as the `canWrite` method on `Resource`.

```jsx
import { useCanWrite, useResource, useString } from '@tomic/react';

const ResourceDescription = () => {
  const resource = useResource('https://my-server.com/my-resource');
  const [description, setDescription] = useString(resource, core.properties.description);
  const [canWrite] = useCanWrite(resource);

  if (canWrite) {
    return (
      <textarea onChange={e => setDescription(e.target.value)}>{description}</textarea>
      <button onClick={() => resource.save()}>Save</button>
    )
  }

  return <p>{description}</p>;
};
```

## Reference

### Parameters

- `resource: Resource` - The resource to check write access for.
- `agent?: Agent` - Optional different agent to check write access for. Defaults to the current agent.

### Returns

Returns a tuple with the following fields:

- `canWrite: boolean` - Whether the agent can write to the resource.
- `msg: string` - An error message if the agent cannot write to the resource.
