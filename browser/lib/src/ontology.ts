import { JSONValue } from './value.js';

export type BaseObject = {
  classes: Record<string, string>;
  properties: Record<string, string>;
};

// Extended via module augmentation
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface Classes {
  'unknown-subject': {
    requires: BaseProps;
    recommends: never;
  };
}

export type UnknownClass = 'unknown-subject';

export type BaseProps =
  | 'https://atomicdata.dev/properties/isA'
  | 'https://atomicdata.dev/properties/parent';

// Extended via module augmentation
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface PropTypeMapping {}

// Extended via module augmentation
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface PropSubjectToNameMapping {}

export type Requires<C extends keyof Classes> = Classes[C]['requires'];
export type Recommends<C extends keyof Classes> = Classes[C]['recommends'];

type PropsOfClass<C extends keyof Classes> = {
  [P in Requires<C>]: P;
} & {
  [P in Recommends<C>]?: P;
};

/**
 * Infers the js type a value can have on a resource for the given property.
 * If the property is not known in any ontology, it will return JSONValue.
 */
export type InferTypeOfValueInTriple<
  Class extends keyof Classes | never = never,
  Prop = string,
  Returns = Prop extends keyof PropTypeMapping
    ? Prop extends Requires<Class>
      ? PropTypeMapping[Prop]
      : PropTypeMapping[Prop] | undefined
    : JSONValue,
> = Returns;

type QuickAccesKnownPropType<Class extends OptionalClass> = {
  readonly [Prop in keyof PropsOfClass<Class> as PropSubjectToNameMapping[Prop]]: InferTypeOfValueInTriple<
    Class,
    Prop
  >;
};

/** Type of the dynamically created resource.props field */
export type QuickAccesPropType<Class extends OptionalClass = UnknownClass> =
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  Class extends UnknownClass ? any : QuickAccesKnownPropType<Class>;

export type OptionalClass = keyof Classes | UnknownClass;

// A map of all known classes and properties to their camelcased shortname.
const globalReverseNameMapping = new Map<string, string>();

/** Let atomic lib know your custom ontologies exist */
export function registerOntologies(...ontologies: BaseObject[]): void {
  for (const ontology of ontologies) {
    for (const [key, value] of Object.entries(ontology.classes)) {
      globalReverseNameMapping.set(value, key);
    }

    for (const [key, value] of Object.entries(ontology.properties)) {
      globalReverseNameMapping.set(value, key);
    }
  }
}

export function getKnownNameBySubject(subject: string): string | undefined {
  return globalReverseNameMapping.get(subject);
}

export function __INTERNAL_GET_KNOWN_SUBJECT_MAPPING(): Map<string, string> {
  return globalReverseNameMapping;
}
