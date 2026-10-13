import {
  core,
  dataBrowser,
  Datatype,
  forms,
  Resource,
  Store,
  CollectionBuilder,
  type Constraint,
} from '@tomic/react';
import { FIELD_TYPE_DEFAULT_OPTIONS, type FormFieldType } from './fieldTypes';
import { columnConstraint } from './formConstraints';

/** Whether the column is a select: its Property is a SelectProperty, or its
 * options are listed in the data class (or the Property's legacy
 * `allowsOnly`). */
function isSelectColumn(property: Resource, constraint: Constraint): boolean {
  return (
    property.hasClasses(dataBrowser.classes.selectProperty) ||
    constraint.enum !== undefined ||
    property.get(core.properties.allowsOnly) !== undefined
  );
}

/** {@link compatibleFieldTypes} for a column of the form's data class. */
export function compatibleColumnTypes(
  store: Pick<Store, 'getResourceLoading'>,
  dataClassSubject: string | undefined,
  property: Resource,
): FormFieldType[] {
  return compatibleFieldTypes(
    property,
    dataClassSubject
      ? columnConstraint(store, dataClassSubject, property.subject)
      : {},
  );
}

/**
 * The presentations a column supports. `constraint` is what applies to the
 * column in the form's data class (see `columnConstraint`): `maxItems: 1`
 * makes a select a single pick, and `class` makes a plain relation a dropdown.
 * Order is significant: the first compatible presentation is the default.
 */
export function compatibleFieldTypes(
  property: Resource,
  constraint: Constraint = {},
): FormFieldType[] {
  const datatype = property.get(core.properties.datatype);

  if (datatype === Datatype.RESOURCEARRAY) {
    if (isSelectColumn(property, constraint)) {
      return constraint.maxItems === 1
        ? ['dropdown', 'radio', 'picture-choice']
        : ['dropdown-multi', 'multi-select'];
    }

    return constraint.class ? ['dropdown'] : [];
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
  const constraint = columnConstraint(
    store,
    dataClass.subject,
    property.subject,
  );
  const type = compatibleFieldTypes(property, constraint)[0];
  if (!type) throw new Error('This column is not supported in forms');
  const options = { ...(FIELD_TYPE_DEFAULT_OPTIONS[type] as object) };
  // The class already caps the pick count; stating it keeps the setting
  // visible in the builder.
  if (constraint.maxItems !== undefined && type === 'dropdown-multi')
    Object.assign(options, { maxItems: constraint.maxItems });

  if (type === 'dropdown' && !isSelectColumn(property, constraint)) {
    const tables = await new CollectionBuilder(store)
      .setProperty(core.properties.classtype)
      .setValue(constraint.class as string)
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
