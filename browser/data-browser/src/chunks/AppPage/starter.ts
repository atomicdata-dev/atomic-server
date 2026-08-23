/**
 * What a new app starts as.
 *
 * Doubles as the contract's documentation: what `view` receives, how to write
 * without asking, and — the part that is easy to get wrong — that an app's own
 * parts are children of the app too, so its data needs somewhere of its own.
 * Someone changing an app, often a model, reads this before anything else, so
 * it is written to be copied.
 */
export const STARTER_APP_SOURCE = `// An app renders into \`root\` and keeps its data under itself.
// \`store\` is the same API as @tomic/lib. No build step, no npm: plain JS.

const NAME = 'https://atomicdata.dev/properties/name';
const PARENT = 'https://atomicdata.dev/properties/parent';

export async function view({ root, store }) {
  const app = await store.getApp();

  // The app's ontology and its view are children of the app as well, so
  // "everything under the app" is not "my data". Keep data under a folder of
  // its own and query that instead.
  const items = await folder(store, app, 'Items');

  const heading = document.createElement('h1');
  heading.textContent = 'New app';

  const add = document.createElement('button');
  add.textContent = 'Add an item';

  const list = document.createElement('ul');

  async function refresh() {
    list.textContent = '';

    for (const subject of await store.query({ property: PARENT, value: items })) {
      const item = await store.getResource(subject);
      const row = document.createElement('li');
      row.textContent = item.get(NAME) ?? subject;
      list.appendChild(row);
    }
  }

  add.onclick = async () => {
    await store.newResource({
      parent: items,
      propVals: { [NAME]: 'Item ' + (list.children.length + 1) },
    });
    await refresh();
  };

  root.append(heading, add, list);
  await refresh();
}

/** The app's folder of that name, made once. */
async function folder(store, app, name) {
  for (const subject of await store.query({ property: PARENT, value: app })) {
    const child = await store.getResource(subject);

    if (child.get(NAME) === name) return subject;
  }

  const made = await store.newResource({ parent: app, propVals: { [NAME]: name } });

  return made.subject;
}
`;
