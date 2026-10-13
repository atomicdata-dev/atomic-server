# Custom Views

Along with a Wasm class extender, plugins can also include a JavaScript bundle to add custom views to the AtomicServer Data Browser.

To enable a custom view, include the `custom-view` permission in your plugin manifest.

## How Custom Views Are Loaded

When a user navigates to a resource whose class is handled by your plugin, the Data Browser renders the custom view inside a **sandboxed, null-origin `<iframe>`**. This means your plugin UI runs in complete isolation from the parent page — it cannot access the parent's DOM, storage, or JavaScript context.

The iframe receives a generated HTML document that:

1. Loads a reset stylesheet.
2. Optionally loads your `ui.css` file.
3. Injects the current theme as CSS custom properties via a `<style>` block: colours such as `--t-color-bg`, `--t-color-text`, `--t-color-main`, `--t-color-alert`, `--t-color-warning` and `--t-color-success`, plus `color-scheme: light` or `dark` on `:root`. The theme message (`{ type: '__atomic_style', css, colorScheme }`, `ThemeMessage` in `@tomic/plugin`) also names `colorScheme: 'light' | 'dark'`, taken from the host's own setting, so a view does not have to guess dark mode from the background colour.
4. Loads your `ui.js` as a `<script type="module">`.

A strict Content Security Policy is applied: only scripts and styles with the correct nonce are allowed to run. External scripts or inline scripts without the nonce will be blocked.

## Bundle Requirements

Because the view is loaded as a single HTML document inside an iframe, **code splitting is not supported**. Your build must produce:

- `ui.js` — a single JavaScript file (no chunks). This file is required.
- `ui.css` — an optional single CSS file.

> [!IMPORTANT]
> It is currently not possible to include external assets (images, fonts, etc.) in your plugin UI. Any assets must be inlined into `ui.js` or `ui.css` (e.g. base64-encoded data URIs).

Configure your bundler to disable code splitting. For example, with Vite + Rolldown:

```ts
// vite.config.ts
export default {
  build: {
    assetsDir: '',
    rolldownOptions: {
      output: {
        codeSplitting: false,
        assetFileNames: 'ui.[ext]',
        entryFileNames: 'ui.js',
      },
    },
  },
};
```

When configured like this, you can still make as many js and css files as you want and they will then be bundled into a single js and css file.

## Choosing a UI Framework

Because the plugin JS bundle must be self-contained and small, **prefer a lightweight framework like [SolidJS](https://www.solidjs.com/)** over React. React (and ReactDOM) add ~130 kB to your bundle, whereas SolidJS compiles away to vanilla DOM operations and adds only a few kilobytes.

The test plugin uses SolidJS with the `vite-plugin-solid` plugin as a reference implementation.

## Communicating with the Data Browser

Since the plugin runs in a sandboxed iframe, it cannot call the Atomic Store or make authenticated requests itself. It asks the Data Browser over `postMessage`, through the `store` object from `@tomic/plugin`.

`store` is shaped after `Store` and `Resource` from [`@tomic/lib`](../js-lib/store.md): if you know how to write `store.getResource(...)`, `resource.set(...)` and `await resource.save()` there, you know how to write a plugin view. Drive apps (views a model writes for you) get the very same object, so the API below covers both kinds of view.

```bash
npm install @tomic/plugin
```

```ts
import { store } from '@tomic/plugin';

const { subject } = await store.getContext();
const page = await store.getResource(subject);

page.set('https://atomicdata.dev/properties/name', 'New name');
await page.save();
```

### Data

| Call | Returns | Notes |
| --- | --- | --- |
| `store.getContext()` | `{ subject, agent? }` | The resource this view shows, and the signed-in agent. |
| `store.getResource(subject)` | `ViewResource` | Asks the person first when it is outside this view's scope (see below). |
| `store.newResource({ parent?, isA?, propVals? })` | `ViewResource` | Created and saved. `parent` defaults to the current page (to the app, for a drive app). |
| `store.query({ property?, value?, filters?, sortBy?, sortDesc?, pageSize?, page? })` | `string[]` | A [collection](../schema/collections.md). Needs a `property` or a filter. Without `page`: every member, at most 500. `pageSize` is 1 to 100, `filters` at most 10 `{ property, value }` pairs. |
| `store.search(text, { isA?, parents?, limit? })` | `string[]` | Full-text search, `limit` 1 to 50 (default 20). |
| `store.subscribe(subject, resource => ...)` | unsubscribe function | Called with the fresh resource on every change. |

| `store.apply(intents)` | `{ subjects }` | Several writes as one change. See below. |
| `store.undo()` | `true`, or `false` when there is nothing to undo | Reverts this view's latest `apply`. |

A `ViewResource` has `subject`, `title`, `props`, `get(property)`, `set(property, value)`, `remove(property)`, `getClasses()`, `hasClasses(...classes)`, `save()` and `destroy()`. Like in `@tomic/lib`, `set` and `remove` only stage a change; `save()` sends what changed since the last save.

`query` and `search` leave out anything this view may not read: a list of subjects already says what exists.

### Several writes as one change

A form builder adds a question by creating a Property, adding it to a class and placing it on a page. Saved one by one, a failure halfway leaves a broken form. `store.apply` takes them together, in the same intent format a plugin's `run()` returns:

```ts
const { subjects } = await store.apply([
  { op: 'create', localId: 'q', parent: ontology, isA: [PROPERTY], set: { [SHORTNAME]: 'age', [DATATYPE]: INTEGER } },
  { op: 'set', subject: rowClass, set: { [RECOMMENDS]: [...current, 'local:q'] } },
]);
subjects.q; // the new Property
```

- **Checked first.** Every value is checked against its property, and every write against this view's access, before anything is written. A problem anywhere means nothing is written.
- **Rolled back.** If a write still fails (the network, the server), the writes before it are reverted and the call rejects.
- **Undoable.** `store.undo()` reverts the latest `apply` as one step, up to 20 back. It refuses, changing nothing, when someone changed those values since.
- **Limits.** At most 200 intents. `destroy` intents run last and are not rolled back; an `apply` that deletes something cannot be undone.

Refer to a resource created in the same call as `local:<localId>`.

### Access control

The plugin can read a resource without any user interaction if any of the following conditions are true:

- The resource is the current page resource (the one the plugin view is rendering).
- The resource's parent is the current page resource.
- Any ancestor of the resource satisfies either of the above.
- The plugin's agent is listed in the resource's (or any ancestor's) `read` or `write` rights.

If none of these conditions are met, the user is shown a **Read Request** dialog asking them to allow or deny access to that specific resource. The user can also check "Allow all reads done by this plugin" to permanently grant the plugin blanket read access. Previously granted permissions are persisted, so the dialog will not appear again for the same resource. If the user denies the request, the promise rejects with an error.

Writes (`save`, `destroy`, `newResource`) follow the same rules for write access, with a **Write Request** dialog when they are not met. Writes are signed by the person's agent.

> [!NOTE]
> Writes that target plugin resources are always blocked, regardless of permissions. A plugin cannot modify itself or any other plugin resource.

A plugin whose view edits schema (a form builder, a table editor) can declare the `edit-schema` capability next to `custom-view`. Once granted at install, its view may write the classes of the resource it shows (and, for a table, the class of its rows), the properties those classes list, and anything in their ontology, without a Write Request each time. A class that sits directly in a drive grants only itself and its properties, never the drive.

Drive apps follow a stricter rule: they read what the signed-in person can read, and write only under their own app resource, signed by the app's own agent.

### Host UI

Some things a frame cannot do well on its own: a menu is cut off at the frame's edge, and a share dialog or a confirmation should look like the rest of Atomic. `store.ui` asks the Data Browser to draw them with its own components. Each one names your plugin to the person, so a prompt can never pass as the Data Browser's own. One question is open at a time: asking a new one answers the open one as cancelled.

| Call | Returns |
| --- | --- |
| `store.ui.confirm({ title, body?, confirmLabel?, danger? })` | `true` or `false` |
| `store.ui.toast(text, { kind? })` | `kind` is `'info'`, `'success'` or `'error'` |
| `store.ui.menu({ at, items })` | The chosen item's `id`, or `null`. `at` is a `MouseEvent` or `{ x, y }` in your frame; `items` are `{ id, label, disabled? }` or `'divider'`, at most 50. |
| `store.ui.resourceMenu(subject, { at })` | Atomic's own menu for a resource: open, share, delete. |
| `store.ui.share(subject)` | Atomic's share dialog. Resolves when it closes. |
| `store.ui.openResource(subject)` | Leaves this view for `subject`. |
| `store.ui.pickResource({ isA?, title? })` | The chosen subject, or `null`. |
| `store.ui.pickFile({ accept? })` | A file's subject, or `null`. The person can upload one; `accept` lists MIME types. |
| `store.ui.form({ class, parent?, propVals? })` | Atomic's own form for a new resource of `class`, saved by the person. The new subject, or `null`. `parent` must be somewhere this view may write. |
| `store.ui.environment()` | `{ locale, placement }` |

Calls that wait on the person (`confirm`, `menu`, `share`, the pickers, `form`) have no timeout. Every other call fails after 60 seconds without an answer.

### Keyboard

Keys your view does not handle are passed to the Data Browser, so its shortcuts (search, Escape to close) keep working while focus is in your view. Only Escape and keys held with Ctrl, Cmd or Alt are passed on, and never the text editing ones (select all, copy, paste, cut, undo, redo). Call `event.preventDefault()` on a key your view handles itself and the Data Browser will not see it.

### How this compares to a phone

The contract borrows from how Android and iOS let apps use what the system offers:

- **System pickers instead of broad access.** Like Android's document picker or iOS's photo picker, `store.ui.pickResource` and `pickFile` let the person choose one thing, without the plugin being able to list everything.
- **Asking at the moment of use.** Reading or writing outside the plugin's scope asks the person then, like a runtime permission, and they can make it permanent.
- **System sheets for system actions.** `share`, `resourceMenu` and `confirm` are the Data Browser's own, like a share sheet or an action sheet, so they behave the same in every plugin.
- **Declared capabilities.** A plugin declares what it will use in its manifest (`custom-view`, `edit-schema`), as an Android manifest or iOS entitlements do, and the person approves it once at install.

### Legacy `RPCClient`

Plugins written before `store` use `new RPCClient()` with `getPageContext`, `getResource`, `commit`, `subscribe`, `navigate`, `pickResource` and `pickFile`. It keeps working, and `rpc.ui` is the same object as `store.ui`, but new plugins should use `store`.

## App frames

A drive app's view (an app made with `createApp`, or an Installation's app) gets a `store` from `/plugin-ui?format=client` instead of an `RPCClient`. It speaks the same versioned wire protocol (`atomic.view.request` / `atomic.view.response`, the `ViewOperation`s in `@tomic/plugin`). Besides the shared `store` calls above, it has these:

#### `store.getMany(subjects): Promise<Array<Resource | { subject, error }>>`

Reads up to 100 resources in one round trip to the host, instead of one `getResource` per row. Each subject is read exactly as `getResource` reads it: through the signed-in person's store, so the app sees what they can see, including their own writes. The array is in the order asked. A subject that cannot be read is `{ subject, error }` in its place, so one missing row does not fail the rest. More than 100 subjects are refused, so ask in batches.

```js
const subjects = await store.query({ property: PARENT, value: table });
const rows = await store.getMany(subjects.slice(0, 100));
for (const row of rows) if (!row.error) render(row.get(NAME));
```

#### `store.getTheme(): { colorScheme: 'light' | 'dark' }` and `store.onThemeChange(handler)`

Whether the host is drawn light or dark, from the host's actual setting. `onThemeChange` calls back with `{ colorScheme }` when the person switches, and returns a function that stops it. For colours, use the `--t-color-*` CSS variables. They change with the theme, so CSS that uses them needs no JavaScript.

```js
const { colorScheme } = store.getTheme();
chart.setDark(colorScheme === 'dark');
store.onThemeChange(({ colorScheme }) => chart.setDark(colorScheme === 'dark'));
```

```css
.saved { color: var(--t-color-success); }
```
