{{#title @tomic/react: Using Atomic Data in a JS / TS React project}}

# @tomic/react: Using Atomic Data in a JS / TS React project

Atomic Data has been designed with front-end development in mind.
The open source [Atomic-Data-Browser](https://github.com/atomicdata-dev/atomic-data-browser), which is feature-packed with chatrooms, a real-time collaborative rich text editor, tables and more, is powered by two libraries:

- `@tomic/lib` ([docs](https://atomicdata-dev.github.io/atomic-data-browser/docs/modules/_tomic_lib.html)) is the core library, containing logic for fetching and storing data, keeping things in sync using websockets, and signing [commits](../commits/intro.md).
- `@tomic/react` ([docs](https://atomicdata-dev.github.io/atomic-data-browser/docs/modules/_tomic_react.html)) is the react library, featuring various useful hooks that mimic `useState`, giving you real-time updates through your app.

Check out the [template on CodeSandbox](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx:0-1223).

This template is a very basic version of the Atomic Data Browser, where you can browse through resources, and see their properties.
There is also some basic editing functionality for descriptions.

<iframe src="https://codesandbox.io/embed/yyd8jx?view=Editor+%2B+Preview&module=%2Fsrc%2Fcomponents%2FBrowser.module.css&hidenavigation=1"
     style="width:100%; height: 500px; border:0; border-radius: 4px; overflow:hidden;"
     title="beautiful-marco-yyd8jx"
     sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
   ></iframe>

Feeling stuck? [Post an issue](https://github.com/atomicdata-dev/atomic-data-browser/issues/new) or [join the discord](https://discord.gg/a72Rv2P).

## Getting Started

### Installation

```bash
npm install @tomic/react
```

### Setup

For Atomic React to work, you need to wrap your app in a `StoreContext.Provider` and provide a [Store](../js-lib/store.md) instance.

```jsx
// App.tsx
import { Store, StoreContext, Agent } from '@tomic/react';

const store = new Store({
  serverUrl: 'my-atomic-server-url',
  agent: Agent.fromSecret('my-agent-secret');
});


export const App = () => {
  return (
    <StoreContext.Provider value={store}>
      ...
    </StoreContext.Provider>
  );
};
```

## Hooks

Atomic React provides a few useful hooks to interact with your atomic data.
Read more about them by clicking on their names

### [useStore](../react/useStore.md)

Easy access to the store instance.

### [useResource](../react/useResource.md)

Fetching and subscribing to resources

### [useValue](../react/useValue.md)

Reading and writing data.

### [useCollection](../react/useCollection.md)

Querying large sets of data.

### [useServerSearch](../react/useServerSearch.md)

Easy full text search.

### [useCurrentAgent](../react/useCurrentAgent.md)

Get the current agent and change it.

### [useCanWrite](../react/useCanWrite.md)

Check for write access to a resource.

## Examples

Find some examples [here](../react/examples.md).
