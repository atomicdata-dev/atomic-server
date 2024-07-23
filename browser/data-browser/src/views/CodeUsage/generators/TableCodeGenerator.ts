import type { DataBrowser, Resource, Store } from '@tomic/react';
import { CodeGenerator } from './CodeGenerator';
import { renderImports, LangEnv } from './generatorUtils';

export class TableCodeGenerator extends CodeGenerator {
  public constructor(
    protected store: Store,
    protected resource: Resource<DataBrowser.Table>,
  ) {
    super(store, resource);
  }

  protected async generateJSCodeBasic() {
    return [
      `import { CollectionBuilder, core, commits } from '@tomic/lib';

// Create a collection containing the children of the table
const table = new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue('${this.resource.subject}')
    .setSortBy(commits.properties.createdAt)
    .build();

// Iterate over the collection, fetch the children and log their title
// Check the docs on how to use collection for other use cases like pagenation
for await (const rowSubject of table) {
  const row = await store.getResource(rowSubject);
  console.log(row.title);
}`,
    ];
  }

  protected async generateJSCodeWithPropUsage(prop: string) {
    const { propImport, propSubjectRef } = await this.getPropertyOntology(prop);
    const imports = renderImports(
      {
        name: 'CollectionBuilder',
        file: '@tomic/lib',
      },
      {
        name: 'core',
        file: '@tomic/lib',
      },
      {
        name: 'commits',
        file: '@tomic/lib',
      },
      propImport,
    );

    return [
      `${imports}
// Create a collection containing the children of the table
const table = new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue('${this.resource.subject}')
    .setSortBy(commits.properties.createdAt)
    .build();

// Iterate over the collection, fetch the children and log a value
// Check the docs on how to use collection for other use cases like pagenation
for await (const rowSubject of table) {
  const row = await store.getResource(rowSubject);
  const value = row.get(${propSubjectRef});
  console.log(\`\${row.title}: \${value}\`);
}`,
    ];
  }

  protected async generateTSCodeBasic() {
    return this.generateJSCodeBasic();
  }

  protected async generateTSCodeWithPropUsage(prop: string) {
    const { propImport, propSubjectRef, resourceShorthand } =
      await this.getPropertyOntology(prop, { resourceVarName: 'row' });

    const { classImport, genericName } = await this.getClassOntology(
      this.resource.props.classtype,
    );

    const imports = renderImports(
      {
        name: 'CollectionBuilder',
        file: '@tomic/lib',
      },
      {
        name: 'core',
        file: '@tomic/lib',
      },
      {
        name: 'commits',
        file: '@tomic/lib',
      },
      !resourceShorthand ? propImport : undefined,
      classImport,
    );

    const valueLine = resourceShorthand
      ? `  console.log(\`\${row.title}: \${${resourceShorthand}}\`);`
      : `  const value = row.get(${propSubjectRef});
  console.log(value);`;

    return [
      `${imports}
// Create a collection containing the children of the table
const table = new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue('${this.resource.subject}')
    .setSortBy(commits.properties.createdAt)
    .build();

// Iterate over the collection, fetch the children and log a value
// Check the docs on how to use collection for other use cases like pagenation
for await (const rowSubject of table) {
  const row = await store.getResource${genericName}(rowSubject);
${valueLine}
}`,
    ];
  }

  protected async generateJSXCodeBasic() {
    return [
      `import {
  commits,
  core,
  useCollection,
  useCollectionPage,
  useResource,
} from '@tomic/react';
import { useState } from 'react';

const Component = () => {
  const [page, setPage] = useState(0);

  const { collection } = useCollection({
    property: core.properties.parent,
    value: '${this.resource.subject}',
    sort_by: commits.properties.createdAt,
  });

  const rows = useCollectionPage(collection, page);

  return (
    <>
      <ul>
        {rows.map(row => (
          <Row key={row} subject={row} />
        ))}
      </ul>
      <button onClick={() => setPage(p => p - 1)}>Prev</button>
      <button onClick={() => setPage(p => p + 1)}>Next</button>
    </>
  );
};

const Row = ({ subject }) => {
  const resource = useResource(subject);

  return <li>{resource.title}</li>;
};`,
    ];
  }

  protected async generateJSXCodeWithPropUsage(prop: string) {
    const { propImport, propSubjectRef } = await this.getPropertyOntology(
      prop,
      { env: LangEnv.React },
    );

    const hook = await this.getHookForProperty(prop);
    const imports = renderImports(
      {
        name: [
          hook,
          'commits',
          'useResource',
          'core',
          'useCollection',
          'useCollectionPage',
        ],
        file: '@tomic/react',
      },
      {
        name: 'useState',
        file: 'react',
      },
      propImport,
    );

    return [
      `${imports}
const Component = () => {
  const [page, setPage] = useState(0);

  const { collection } = useCollection({
    property: core.properties.parent,
    value: '${this.resource.subject}',
    sort_by: commits.properties.createdAt,
  });

  const rows = useCollectionPage(collection, page);

  return (
    <>
      <ul>
        {rows.map(row => (
          <Row key={row} subject={row} />
        ))}
      </ul>
      <button onClick={() => setPage(p => p - 1)}>Prev</button>
      <button onClick={() => setPage(p => p + 1)}>Next</button>
    </>
  );
};

const Row = ({ subject }) => {
  const row = useResource(subject);
  const [value] = ${hook}(row, ${propSubjectRef});

  return <li>{resource.title}: {value}</li>;
};`,
    ];
  }

  protected async generateTSXCodeBasic() {
    return this.generateJSXCodeBasic();
  }

  protected async generateTSXCodeWithPropUsage(prop: string) {
    const { propSubjectRef, resourceShorthand } =
      await this.getPropertyOntology(prop, {
        env: LangEnv.React,
        resourceVarName: 'row',
      });

    const { classImport, genericName } = await this.getClassOntology(
      this.resource.getClasses()[0],
      LangEnv.React,
    );

    const hook = await this.getHookForProperty(prop);
    const imports = renderImports(
      !resourceShorthand
        ? {
            name: hook,
            file: '@tomic/react',
          }
        : undefined,
      {
        name: [
          'commits',
          'useResource',
          'core',
          'useCollection',
          'useCollectionPage',
        ],
        file: '@tomic/react',
      },
      {
        name: 'useState',
        file: 'react',
      },
      classImport,
    );

    const propUsage = resourceShorthand
      ? `
  return <li>{row.title}: {${resourceShorthand}}</div>;`
      : `  const [value] = ${hook}(resource, ${propSubjectRef});

  return <li>{row.title}: {value}</li>;`;

    return [
      `${imports}
const Component = () => {
  const [page, setPage] = useState(0);

  const { collection } = useCollection({
    property: core.properties.parent,
    value: '${this.resource.subject}',
    sort_by: commits.properties.createdAt,
  });

  const rows = useCollectionPage(collection, page);

  return (
    <>
      <ul>
        {rows.map(row => (
          <Row key={row} subject={row} />
        ))}
      </ul>
      <button onClick={() => setPage(p => p - 1)}>Prev</button>
      <button onClick={() => setPage(p => p + 1)}>Next</button>
    </>
  );
};

const Row = ({ subject }: { subject: string }) => {
  const row = useResource${genericName}(subject);
${propUsage}
};`,
    ];
  }

  protected async generateSvelteCodeBasic() {
    return [
      // Component code
      `// Component.svelte
<script>
  import { CollectionBuilder } from '@tomic/lib';
  import { store } from '@tomic/svelte';

  let page = 0;
  let items = [];

  // Create a collection containing the children of the table
  const table = new CollectionBuilder($store)
    .setProperty(core.properties.parent)
    .setValue('${this.resource.subject}')
    .setSortBy(commits.properties.createdAt)
    .build();

  $: table.getMembersOnPage(page).then(members => {
    items = members;
  });
</script>

<ul>
  {#each items as item (item)}
    <li>
      <Item subject={item} />
    </li>
  {/each}
</ul>
<button on:click={() => page -= 1}>Prev</button>
<button on:click={() => page += 1}>Next</button>`,
      // Item code
      `// Item.svelte
<script>
  import { getResource } from '@tomic/svelte';

  export let subject: string;

  let resource = getResource(subject);
</script>

<span>{$resource.title}</span>`,
    ];
  }

  protected async generateSvelteCodeWithPropUsage(prop: string) {
    const { propImport, propSubjectRef } = await this.getPropertyOntology(prop);

    const imports = renderImports(
      '  ',
      {
        name: 'getResource',
        file: '@tomic/svelte',
      },
      {
        name: 'getValue',
        file: '@tomic/svelte',
      },
      propImport,
    );

    return [
      // Component code
      `// Component.svelte
<script>
  import { CollectionBuilder } from '@tomic/lib';
  import { store } from '@tomic/svelte';

  let page = 0;
  let items = [];

  // Create a collection containing the children of the table
  const table = new CollectionBuilder($store)
    .setProperty(core.properties.parent)
    .setValue('${this.resource.subject}')
    .setSortBy(commits.properties.createdAt)
    .build();

  $: table.getMembersOnPage(page).then(members => {
    items = members;
  });
</script>

<ul>
  {#each items as item (item)}
    <li>
      <Item subject={item} />
    </li>
  {/each}
</ul>
<button on:click={() => page -= 1}>Prev</button>
<button on:click={() => page += 1}>Next</button>`,
      // Item code
      `// Item.svelte
<script>
${imports}
  export let subject: string;

  let resource = getResource(subject);
  let value = getValue(resource, ${propSubjectRef});
</script>

<span>{$resource.title}: {$value}</span>`,
    ];
  }

  protected async generateSvelteTSCodeBasic() {
    return [
      // Component code
      `// Component.svelte
<script lang='ts'>
  import { CollectionBuilder } from '@tomic/lib';
  import { store } from '@tomic/svelte';

  let page = 0;
  let items = [];

  // Create a collection containing the children of the table
  const table = new CollectionBuilder($store)
    .setProperty(core.properties.parent)
    .setValue('${this.resource.subject}')
    .setSortBy(commits.properties.createdAt)
    .build();

  $: table.getMembersOnPage(page).then(members => {
    items = members;
  });
</script>

<ul>
  {#each items as item (item)}
    <li>
      <Item subject={item} />
    </li>
  {/each}
</ul>
<button on:click={() => page -= 1}>Prev</button>
<button on:click={() => page += 1}>Next</button>`,
      // Item code
      `// Item.svelte
<script lang='ts'>
  import { getResource } from '@tomic/svelte';

  export let subject: string;

  let resource = getResource(subject);
</script>

<span>{$resource.title}</span>`,
    ];
  }

  protected async generateSvelteTSCodeWithPropUsage(prop: string) {
    const { classImport, genericName } = await this.getClassOntology(
      this.resource.props.classtype,
    );
    const { propImport, propSubjectRef, resourceShorthand } =
      await this.getPropertyOntology(prop);

    const itemImports = renderImports(
      '  ',
      classImport,
      {
        name: 'getResource',
        file: '@tomic/svelte',
      },
      {
        name: 'getValue',
        file: '@tomic/svelte',
      },
      resourceShorthand ? undefined : propImport,
    );

    const hookPart = resourceShorthand
      ? ''
      : `\n  let value = getValue(resource, ${propSubjectRef});`;

    return [
      // Component code
      `// Component.svelte
<script lang='ts'>
  import { CollectionBuilder } from '@tomic/lib';
  import { store } from '@tomic/svelte';

  let page = 0;
  let items = [];

  // Create a collection containing the children of the table
  const table = new CollectionBuilder($store)
    .setProperty(core.properties.parent)
    .setValue('${this.resource.subject}')
    .setSortBy(commits.properties.createdAt)
    .build();

  $: table.getMembersOnPage(page).then(members => {
    items = members;
  });
</script>

<ul>
  {#each items as item (item)}
    <li>
      <Item subject={item} />
    </li>
  {/each}
</ul>
<button on:click={() => page -= 1}>Prev</button>
<button on:click={() => page += 1}>Next</button>`,
      // Item code
      `// Item.svelte
<script lang='ts'>
${itemImports}
  export let subject: string;

  let resource = getResource${genericName}(subject);${hookPart}
</script>

<span>{$resource.title}: {${resourceShorthand ?? '$value'}}</span>`,
    ];
  }
}
