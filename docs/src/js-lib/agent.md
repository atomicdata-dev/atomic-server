# Agents

An agent is an authenticated identity that can interact with Atomic Data resources.
All writes in AtomicServer are signed by an agent and can therefore be proven to be authentic.
Read more about agents in the [Atomic Data specification](../agents.md).

## Creating an Agent instance

Creating an agent can be done in two ways, either by using the `Agent` constructor or by using the `Agent.fromSecret` method.

```typescript
const agent = new Agent('my-private-key', 'my-agent-subject');
```

```typescript
const agent = Agent.fromSecret('my-long-secret-string');
```
