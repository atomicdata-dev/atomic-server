# useCurrentAgent

`useCurrentAgent` is a convenient hook that returns the current agent set in the store.
It also allows you to change the agent.

It also updates whenever the agent changes.

```ts
const [agent, setAgent] = useCurrentAgent();
```

## Reference

### Parameters

none

### Returns

Returns a tuple with the following fields:

- `agent: Agent` - The current agent set on the store.
- `setAgent: (agent: Agent) => void` - A function to set the current agent on the store.
