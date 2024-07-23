# useStore

You can use `useStore` when you need direct access to the store in your components.

For example, on a login screen, you might want to set the agent on the store by calling `store.setAgent` after the user has entered their agent secret.

```jsx
import { Agent, useStore } from '@tomic/react';

export const Login = () => {
  const store = useStore();
  const [agentSecret, setAgentSecret] = useState('');

  const login = () => {
    try {
      const newAgent = Agent.fromSecret(agentSecret);
      store.setAgent(newAgent);
    } catch(e) {
      console.error(e);
      // Show error.
    }
  };

  return (
    <label>
      Secret
      <input
        type="password"
        placeholder="My Secret"
        value={agentSecret}
        onChange={e => setAgentSecret(e.target.value)}
      />
    </label>
    <button onClick={login}>Login</button>
  );
};
```

## Reference

### Paramaters

None.

### Returns

[Store](../js-lib/store.md) - The store object.
