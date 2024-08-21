import {
  CollectionBuilder,
  Datatype,
  core,
  type Core,
  type Resource,
  type Store,
} from '@tomic/react';
import {
  LangEnv,
  toCamelCase,
  toPascaleCase,
  type ImportItem,
} from './generatorUtils';

export enum GeneratorLanguage {
  JS = 'js',
  TS = 'ts',
  JSX = 'jsx',
  TSX = 'tsx',
  Svelte = 'svelte',
  SvelteTS = 'svelte-ts',
}

interface CodeGeneratorOptions {
  language: GeneratorLanguage;
  property?: string;
}

interface OntologyPropertySnippets {
  propImport?: ImportItem;
  resourceShorthand?: string;
  propSubjectRef: string;
}

interface OntologyClassSnippets {
  classImport?: ImportItem;
  genericName?: string;
}

const includeOntologies = new Set([
  'https://atomicdata.dev/ontology/core',
  'https://atomicdata.dev/ontology/commit',
  'https://atomicdata.dev/ontology/collections',
  'https://atomicdata.dev/ontology/data-browser',
  'https://atomicdata.dev/ontology/server',
]);

export abstract class CodeGenerator {
  public constructor(
    protected store: Store,
    protected resource: Resource,
  ) {}

  public generateWithOptions({
    language,
    property,
  }: CodeGeneratorOptions): Promise<string[]> {
    switch (language) {
      case GeneratorLanguage.JS:
        return property
          ? this.generateJSCodeWithPropUsage(property)
          : this.generateJSCodeBasic();
      case GeneratorLanguage.TS:
        return property
          ? this.generateTSCodeWithPropUsage(property)
          : this.generateTSCodeBasic();
      case GeneratorLanguage.JSX:
        return property
          ? this.generateJSXCodeWithPropUsage(property)
          : this.generateJSXCodeBasic();
      case GeneratorLanguage.TSX:
        return property
          ? this.generateTSXCodeWithPropUsage(property)
          : this.generateTSXCodeBasic();
      case GeneratorLanguage.Svelte:
        return property
          ? this.generateSvelteCodeWithPropUsage(property)
          : this.generateSvelteCodeBasic();
      case GeneratorLanguage.SvelteTS:
        return property
          ? this.generateSvelteTSCodeWithPropUsage(property)
          : this.generateSvelteTSCodeBasic();
      default:
        throw new Error('Invalid language');
    }
  }

  protected async getPropertyOntology(
    property: string,
    {
      env = LangEnv.Other,
      resourceVarName = 'resource',
    }: { env?: LangEnv; resourceVarName?: string } = {},
  ): Promise<OntologyPropertySnippets> {
    const ontologySubject = await this.getReferencedOntology(
      property,
      'property',
    );

    if (!ontologySubject) {
      return {
        propSubjectRef: `'${property}'`,
        resourceShorthand: undefined,
        propImport: undefined,
      };
    }

    const [propResource, ontology] = await Promise.all([
      this.store.getResource<Core.Property>(property),
      this.store.getResource(ontologySubject),
    ]);

    const ontName = toCamelCase(ontology.title);
    const propName = toCamelCase(propResource.props.shortname);

    return {
      propImport: this.isOntologyIncludedInLib(ontology.subject)
        ? {
            name: ontName,
            file: getLibForEnv(env),
          }
        : {
            name: ontName,
            file: './ontologies',
          },
      propSubjectRef: `${ontName}.properties.${propName}`,
      resourceShorthand: `${resourceVarName}.props.${propName}`,
    };
  }

  protected async getClassOntology(
    classSubject: string,
    env: LangEnv = LangEnv.Other,
  ): Promise<OntologyClassSnippets> {
    const ontologySubject = await this.getReferencedOntology(
      classSubject,
      'class',
    );

    if (!ontologySubject) {
      return {
        classImport: undefined,
        genericName: undefined,
      };
    }

    const [classResource, ontology] = await Promise.all([
      this.store.getResource(classSubject),
      this.store.getResource(ontologySubject),
    ]);

    const pascalOntName = toPascaleCase(ontology.title);
    const classTypeName = toPascaleCase(classResource.title);

    const genericName = this.isOntologyIncludedInLib(ontology.subject)
      ? `<${pascalOntName}.${classTypeName}>`
      : `<${classTypeName}>`;

    return {
      classImport: this.isOntologyIncludedInLib(ontology.subject)
        ? {
            name: `type ${pascalOntName}`,
            file: getLibForEnv(env),
          }
        : {
            name: `type ${classTypeName}`,
            file: './ontologies',
          },
      genericName,
    };
  }

  protected async getReferencedOntology(
    subject: string,
    type: 'property' | 'class',
  ): Promise<string | undefined> {
    const origin = new URL(subject).origin;
    const collection = await new CollectionBuilder(this.store, origin)
      .setProperty(
        type === 'property'
          ? core.properties.properties
          : core.properties.classes,
      )
      .setValue(subject)
      .buildAndFetch();

    try {
      return await collection.getMemberWithIndex(0);
    } catch (e) {
      return undefined;
    }
  }

  protected async getHookForProperty(prop: string) {
    const property = await this.store.getResource<Core.Property>(prop);

    switch (property.props.datatype) {
      case Datatype.STRING:
      case Datatype.SLUG:
      case Datatype.MARKDOWN:
      case Datatype.DATE:
        return 'useString';
      case Datatype.BOOLEAN:
        return 'useBoolean';
      case Datatype.INTEGER:
      case Datatype.FLOAT:
      case Datatype.TIMESTAMP:
        return 'useNumber';
      case Datatype.ATOMIC_URL:
        return 'useSubject';
      case Datatype.RESOURCEARRAY:
        return 'useArray';
      default:
        return 'useValue';
    }
  }

  protected isOntologyIncludedInLib(subject: string) {
    return includeOntologies.has(subject);
  }

  protected abstract generateJSCodeBasic(): Promise<string[]>;

  protected abstract generateJSCodeWithPropUsage(
    prop: string,
  ): Promise<string[]>;

  protected abstract generateTSCodeBasic(): Promise<string[]>;

  protected abstract generateTSCodeWithPropUsage(
    prop: string,
  ): Promise<string[]>;

  protected abstract generateJSXCodeBasic(): Promise<string[]>;

  protected abstract generateJSXCodeWithPropUsage(
    prop: string,
  ): Promise<string[]>;
  protected abstract generateTSXCodeBasic(): Promise<string[]>;

  protected abstract generateTSXCodeWithPropUsage(
    prop: string,
  ): Promise<string[]>;

  protected abstract generateSvelteCodeBasic(): Promise<string[]>;

  protected abstract generateSvelteCodeWithPropUsage(
    prop: string,
  ): Promise<string[]>;
  protected abstract generateSvelteTSCodeBasic(): Promise<string[]>;

  protected abstract generateSvelteTSCodeWithPropUsage(
    prop: string,
  ): Promise<string[]>;
}

const getLibForEnv = (env: LangEnv) => {
  return env === LangEnv.React ? '@tomic/react' : '@tomic/lib';
};
