import {
  core,
  dataBrowser,
  Datatype,
  forms,
  Resource,
  Store,
  CollectionBuilder,
} from '@tomic/react';
import { FIELD_TYPE_DEFAULT_OPTIONS, type FormFieldType } from './fieldTypes';

/** Order is significant: the first compatible presentation is the default. */
export function compatibleFieldTypes(property: Resource): FormFieldType[] {
  const datatype = property.get(core.properties.datatype);

  if (datatype === Datatype.RESOURCEARRAY) {
    if (
      property.hasClasses(dataBrowser.classes.selectProperty) ||
      property.get(core.properties.allowsOnly) !== undefined
    ) {
      return property.get(dataBrowser.properties.max) === 1
        ? ['dropdown', 'radio', 'picture-choice']
        : ['dropdown-multi', 'multi-select'];
    }

    return property.get(core.properties.classtype) ? ['dropdown'] : [];
  }

  switch (datatype) {
    case Datatype.STRING:
      return ['short-text', 'long-text', 'email', 'phone', 'url', 'country'];
    case Datatype.FLOAT:
      return ['number', 'currency'];
    case Datatype.INTEGER:
      return ['number', 'likert', 'rating'];
    case Datatype.BOOLEAN:
      return ['checkbox'];
    case Datatype.DATE:
      return ['date'];
    case Datatype.TIMESTAMP:
      return ['datetime'];
    default:
      return [];
  }
}

export function classColumns(dataClass: Resource): string[] {
  return [
    ...new Set([
      ...dataClass.getSubjects(core.properties.requires),
      ...dataClass.getSubjects(core.properties.recommends),
    ]),
  ];
}

export function columnLabel(property: Resource): string {
  return (
    (property.get(core.properties.name) as string) ||
    (property.get(core.properties.shortname) as string) ||
    property.subject
  );
}

/** Creates presentation only. Never writes to the class, Property, or Tags. */
export async function createMappedField(
  store: Store,
  page: Resource,
  dataClass: Resource,
  property: Resource,
): Promise<Resource> {
  if (!classColumns(dataClass).includes(property.subject))
    throw new Error('Column is not part of this table');
  const type = compatibleFieldTypes(property)[0];
  if (!type) throw new Error('This column is not supported in forms');
  const options = { ...(FIELD_TYPE_DEFAULT_OPTIONS[type] as object) };
  const max = property.get(dataBrowser.properties.max) as number | undefined;
  if (max !== undefined && type === 'dropdown-multi')
    Object.assign(options, { maxSelected: max });

  if (
    type === 'dropdown' &&
    property.get(core.properties.allowsOnly) === undefined
  ) {
    const tables = await new CollectionBuilder(store)
      .setProperty(core.properties.classtype)
      .setValue(property.get(core.properties.classtype) as string)
      .setFilters([
        { property: core.properties.isA, value: dataBrowser.classes.table },
      ])
      .buildAndFetch();
    let target: string | undefined;

    for await (const subject of tables) {
      target = subject;
      break;
    }

    if (!target) throw new Error('No table found for this relation column');
    Object.assign(options, { optionsSource: { table: target } });
  }

  const field = await store.newResource({
    parent: page.subject,
    isA: forms.classes.formField,
    propVals: {
      [core.properties.name]: columnLabel(property),
      [forms.properties.formMapsTo]: property.subject,
      [forms.properties.formFieldType]: type,
      [forms.properties.required]: dataClass
        .getSubjects(core.properties.requires)
        .includes(property.subject),
      [forms.properties.formFieldOptions]: options,
    },
  });
  await field.save();

  return field;
}
