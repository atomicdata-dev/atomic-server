# Views Readme

Views are a special type of components.
They are the ones rendering the actual Resources.
Views render only one or more classes.
If there is no View available for a specific Class, it will fall back to the `ResourceX` component (e.g. `ResourceCard`).

Some notes:

- Every View is passed a `Resource` property. Some ViewType have additional properties, which should be documented here.
- When naming a View, use the `ClassnameViewType.tsx` naming convention (e.g. `PersonCard`).
- When adding a ViewType, document it here and implement a generic Resource renderer. Also make sure that it has error handling and adds the `about` RDFa attribute.
- Views starting with `Resource` in the name are responsible for registering the other class specific Views.

## View Types

Since views will occur in some context (e.g. full page vs inside a small card), they need to be registered for a certain View Type.
The following view types currently exist, from large to small:

### Page

A full page Resource.
This is what is shown when opening the URL of the resource.

### Card

A smaller, contained version. Shown in grid views and in search results.

Properties:

- `small`: boolean. Will hide even more elements.
- `selected`: boolean. Adds a border to the item.

### Line

A Resource inside a single (full width) line.
Used in lists.

### Inline

Can appear inside a sentence of text, or inside a table.
One of the smallest View Types.

## Adding a new View

Depending on the ViewType, make sure to add your new component to the respective `switch` statement in e.g. `ResourcePage` or `ResourceCard`.
