import { CodeGenerator } from './CodeGenerator';
import { renderImports, LangEnv } from './generatorUtils';

export class BasicCodeGenerator extends CodeGenerator {
  protected async generateJSCodeBasic() {
    return [
      `const resource = await store.getResource('${this.resource.subject}');`,
    ];
  }

  protected async generateJSCodeWithPropUsage(prop: string) {
    const { propImport, propSubjectRef } = await this.getPropertyOntology(prop);
    const imports = renderImports(propImport);

    return [
      `${imports}${await this.generateJSCodeBasic()}
const value = resource.get(${propSubjectRef});
`,
    ];
  }

  protected async generateTSCodeBasic() {
    const { classImport, genericName } = await this.getClassOntology(
      this.resource.getClasses()[0],
    );

    const imports = renderImports(classImport);

    return [
      `${imports}const resource = await store.getResource${genericName ?? ''}('${this.resource.subject}');`,
    ];
  }

  protected async generateTSCodeWithPropUsage(prop: string) {
    const { resourceShorthand } = await this.getPropertyOntology(prop);

    return [
      `${await this.generateTSCodeBasic()}
const value = ${resourceShorthand ?? `resource.get('${prop}')`};
`,
    ];
  }

  protected async generateJSXCodeBasic() {
    const imports = renderImports({
      name: 'useResource',
      file: '@tomic/react',
    });

    return [
      `${imports}const Component = () => {
  const resource = useResource('${this.resource.subject}');

  return <div>{resource.title}</div>;
}`,
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
        name: [hook, 'useResource'],
        file: '@tomic/react',
      },
      propImport,
    );

    return [
      `${imports}
const Component = () => {
  const resource = useResource('${this.resource.subject}');
  const [value] = ${hook}(resource, ${propSubjectRef});

  return <div>{value}</div>;
}`,
    ];
  }

  protected async generateTSXCodeBasic() {
    return this.generateJSXCodeBasic();
  }

  protected async generateTSXCodeWithPropUsage(prop: string) {
    const { propSubjectRef, resourceShorthand } =
      await this.getPropertyOntology(prop, { env: LangEnv.React });

    const { classImport, genericName } = await this.getClassOntology(
      this.resource.getClasses()[0],
      LangEnv.React,
    );

    const hook = await this.getHookForProperty(prop);
    // Only import the hook if we can't use the shorthand.
    const imports = renderImports(
      !resourceShorthand
        ? {
            name: hook,
            file: '@tomic/react',
          }
        : undefined,
      {
        name: 'useResource',
        file: '@tomic/react',
      },
      classImport,
    );

    const propUsage = resourceShorthand
      ? `
  return <div>{${resourceShorthand}}</div>;`
      : `  const [value] = ${hook}(resource, ${propSubjectRef});

  return <div>{value}</div>;`;

    return [
      `${imports}
const Component = () => {
  const resource = useResource${genericName}('${this.resource.subject}');
${propUsage}
}`,
    ];
  }

  protected async generateSvelteCodeBasic() {
    const imports = renderImports({
      name: 'getResource',
      file: '@tomic/svelte',
    });

    return [
      `<script>
  ${imports}
  let resource = getResource('${this.resource.subject}');
</script>

<div>{$resource.title}</div> `,
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
      `<script>
${imports}
  let resource = getResource('${this.resource.subject}');
  let value = getValue(resource, ${propSubjectRef});
</script>

<div>{$value}</div>`,
    ];
  }

  protected async generateSvelteTSCodeBasic() {
    const imports = renderImports({
      name: 'getResource',
      file: '@tomic/svelte',
    });

    return [
      `<script lang='ts'>
  ${imports}
  let resource = getResource('${this.resource.subject}');
</script>

<div>{$resource.title}</div>`,
    ];
  }

  protected async generateSvelteTSCodeWithPropUsage(prop: string) {
    const { classImport, genericName } = await this.getClassOntology(
      this.resource.getClasses()[0],
    );
    const { propImport, propSubjectRef, resourceShorthand } =
      await this.getPropertyOntology(prop);

    const imports = renderImports(
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
      `<script lang='ts'>
${imports}
  let resource = getResource${genericName}('${this.resource.subject}');${hookPart}
</script>

<div>{${resourceShorthand ?? '$value'}}</div> `,
    ];
  }
}
