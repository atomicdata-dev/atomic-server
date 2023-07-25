# Atomic Data Browser

[![Build Status](https://github.com/atomicdata-dev/atomic-data-browser/workflows/build/badge.svg)](https://github.com/atomicdata-dev/atomic-data-browser/actions)

_Status: Beta. [Breaking changes](CHANGELOG.md) are expected until 1.0._

View, edit and create [Atomic Data](https://atomicdata.dev/) from your browser!
Designed for interacting with [`atomic-server`](https://github.com/atomicdata-dev/atomic-data-browser).

**[demo on atomicdata.dev](https://atomicdata.dev/)**

## Features

- **View data**
  - Browse and fetch Atomic Data
  - Render [properties](https://atomicdata.dev/classes/Property) from any resource
  - Table & Grid views with sorting / pagination powered by [Collections](https://atomicdata.dev/classes/Collection)
  - Data viewer to render data in [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html), Turtle, JSON-LD, and more.
- **Edit data**
  - Dynamic forms for creating and editing resources with datatype validation. Powered by [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html).
  - Create, send and sign [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html). All changes are cryptographically signed.
  - Accept [Invites](https://docs.atomicdata.dev/invitations.html), manage user [Agents](https://docs.atomicdata.dev/agents.html) (including private keys) and Servers.
  - [Authorization] - view and edit permissions in the [hierarchy](https://docs.atomicdata.dev/hierarchy.html).
  - [Authentication](https://docs.atomicdata.dev/authentication.html) - all requests are signed.
  - History view + revert to older versions
- **Other**
  - Document editor with Markdown & real-time sync / collaboration (using WebSockets)
  - Import webpages and convert them to Markdown for personal backups
  - Group chat rooms
  - Collapsible sidebar for easy navigation
  - UI customization: dark mode, navigation bar placement and theme colour
  - Responsive, accessible, keyboard controls
  - Upload, preview and download [files](https://docs.atomicdata.dev/files.html)
  - Monetize content using WebMonetization! Thanks to Grant For the Web + Interledger.

## Running locally

```sh
# Install dependencies
pnpm
# Run dev server
pnpm start
# Open browser at http://localhost:5173
```

If you want to _edit_ data, you'll need an [_Agent_](https://atomicdata.dev/classes/Agent), including its `privateKey` and `subject`.
You can get one by accepting [an Invite](https://atomicdata.dev/invites/1), or by hosting your own [`atomic-server`](https://github.com/atomicdata-dev/atomic-data-rust/blob/master/server/README.md).
You can set the Agent on the `/app/agent` route.

## Understanding & contributing to the code

- **Routing** is firstly done using React Router, and secondly using the ResourcePage component. This component checks the Class of the Resource, and decides which view is most suitable. Users can open Data views and Edit forms for any resource. We have some basic routes for showing, editing, and searching. Many of these routes use query parameters. The `/app` routes should be used for most app functionality, which will make the chance of having path collisions with a server smaller.
- **Styling** is done using [styled components](https://styled-components.com/). The theme settings in `Styling.tsx` desribe colors, border radius and margin size. Use these as variables in components to make sure that users can change style preferences (e.g. dark mode, accent color, font, margin size)
- **Data fetching** is handled by the `Store`, which makes sure that you don't ask twice for the same resource and let's other resources know that things have changed.
- **Hooks** are used wherever possible. This means functional components, instead of old-style Class components. Hooks tend to use a pattern similar to React's own `useState`, which means that two terms are returned: the first one contains the current value, and the second one is a function for setting the value.
- **Document** your components and properties! Explain your thinking when doing something non-trivial.
- **Resources** should have a `about={subject}` tag in HTML elements / DOM nodes, which can be used for debugging and RDFa parsing. This means that you can press `e` to edit anything you're hovering on, or press `d` to show the data!
- **Creating views** for new types of Resources should be done in `/views`. Check the README.md in that folder.
- **Fetching & processing** is done in this order. The UI renders some component that uses `useResource`, and passes a `subject` URL. This is probably first the one that's shown in the navigation bar. This resource is fetched (unless it's already in the store) as a `JSON-AD` object, after which it is put in the Store without any changes. The Parser does not perform validation checks - that would make the application slower. After the resource is added to the store, subscribers (users of that resource, such as Components with the `useResource` hook) will be notified of changes. The component will re-render, and the props can now be used.
- **Accessing the store from the browser console** can be done in develop mode in your browser with the global `store` object.
- **Forms** use the various value hooks (e.g. `useString`) for maintaining actual resource state. When the form input changes, the new value will be `.set()` on the `Resource`, and this will throw an error if there is a validation error. These should be catched by passing an error handler to the `useString` hook.
- **Error handling** is set in `App.tsx` on initialization. We set `Store.errorHandler` which is called when something goes wrong. This should result in a toaster error shown to the user, and a message sent to BugSnag if `window.bugsnagApiKey` is set.
- **Bundle Splitting** is used for components that use a large dependancy that is not vital to the main application. These component are located in the `chunks` folder and should **always** be imported dynamically to avoid adding the dependancy to the main bundle.

## Directory structure

- **components**: project specific components.
  - **datatypes**: for viewing atomic datatypes.
  - **forms**: for handling forms and form fields
- **views**: components that render specific Classes. See [the views README](src/views/README.md)
- **routes**: components that use the Router to decide what to render.
- **helpers**: projects-specific helper functions
- **atomic-lib**: general atomic data library, containing logic for the store, parsing, sending requests, the Resource model, datatype validations, creating Commits and more. Should not contain any react-specific code.
- **atomic-react**: generic, yet react-specific library with hooks for viewing and manipulating atomic data. Contains re-usable react specific logic.
- **routes**: components that are fed into the React Router as main Routes (e.g. `/show`, `/app/theme`).

## Testing

The tests are located in `tests` and have `.spec` in their filename.
They use the PlayWright framework and run in the browser.

- make sure the data-browser server is running (`pnpm start`) at `http://localhost:5173`
- make sure an [`atomic-server`](https://crates.io/crates/atomic-server/) instance is running at `http://localhost:9883`
- make sure the `http://localhost/setup` invite has at least one available usage. You can set a higher amount [here](http://localhost/app/edit?subject=http%3A%2F%2Flocalhost%2Fsetup), or run `atomic-server --inititalize` to reset it to 1.
- Install the Playwright dependencies: `pnpm playwright-install`
- `pnpm test` launches the E2E tests (make sure the dev server is running at `http://localhost:5173`)
- `pnpm test-debug` launches the E2E tests in debug mode (a window opens with debug tools)
- `pnpm test-new` create new tests by clicking through the app
- Use the `data-test` attribute in HTML elements to make playwright tests more maintainable (and prevent failing tests on changing translations)
- `pnpm test-query {word}` run e2e tests in debug mode containing `{word}`

## CI

GitHub Action / Workflow is used for:

- Linting (ESlint)
- Building
- Testing (in the browser using `playwright`, using an `atomic-server` docker image)

## Contribute

Open a PR, post an issue, but most of all: [join our Discord server](https://discord.gg/a72Rv2P)!
