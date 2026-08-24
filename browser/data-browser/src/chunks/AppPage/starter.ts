/**
 * What a new app starts as.
 *
 * Doubles as the contract's documentation: what `view` receives, and — the
 * part worth getting right — that an app's rows belong in its table rather
 * than in a list the app draws itself. Someone changing an app, often a
 * model, reads this before anything else, so it is written to be copied.
 */
export const STARTER_APP_SOURCE = `// An app renders into \`root\` and keeps its rows in its own table.
// \`store\` is the same API as @tomic/lib. No build step, no npm: plain JS.

const NAME = 'https://atomicdata.dev/properties/name';
const PARENT = 'https://atomicdata.dev/properties/parent';

export async function view({ root, store }) {
  // The app's table, and the class its rows are. Rows created here show up in
  // the table view too — sortable, filterable and editable — without this
  // file implementing any of that.
  const { table, rowClass } = await store.getData();

  const heading = document.createElement('h1');
  heading.textContent = 'New app';

  const add = document.createElement('button');
  add.textContent = 'Add an item';

  const list = document.createElement('ul');

  async function refresh() {
    list.textContent = '';

    for (const subject of await store.query({ property: PARENT, value: table })) {
      const row = await store.getResource(subject);
      const item = document.createElement('li');
      item.textContent = row.get(NAME) ?? subject;
      list.appendChild(item);
    }
  }

  add.onclick = async () => {
    await store.newResource({
      parent: table,
      isA: [rowClass],
      propVals: { [NAME]: 'Item ' + (list.children.length + 1) },
    });
    await refresh();
  };

  root.append(heading, add, list);
  await refresh();
}
`;
