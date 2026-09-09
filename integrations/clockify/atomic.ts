/** Atomic-side table installation helpers. Provider logic stays in plugin.ts. */
import {
  core,
  dataBrowser,
  findSchema,
  readConnectionSubjects,
  timeTrackingSchema,
  type Store,
  type EnsuredSchema,
} from '../../browser/lib/src/index.js';

export interface TimeTableTarget {
  tableSubject: string;
  classSubject: string;
  name: string;
  schema: EnsuredSchema;
}

/** Match identities and datatypes, never display names. This lookup is read-only. */
export async function timeTrackerTables(
  store: Store,
  drive: string,
): Promise<TimeTableTarget[]> {
  const spec = timeTrackingSchema();
  const schema = await findSchema(store, drive, spec);
  const properties = schema.properties;
  const classes = schema.classes;
  const mapped = [
    'work-start',
    'work-end',
    'work-project',
    'work-person',
    'work-billable',
  ];
  if (
    mapped.some(key => !properties?.[key]) ||
    !properties?.['work-source-id'] ||
    !classes?.['work-person'] ||
    !classes?.['work-project']
  )
    return [];
  // Project is optional in Clockify; a table requiring it is not generally importable.
  const supplied = [
    core.properties.name,
    ...Object.entries(properties)
      .filter(([key]) => key !== 'work-project')
      .map(([, value]) => value),
  ];
  for (const key of ['work-project', 'work-person']) {
    const resource = await store.getResource(classes[key]);
    const requires = resource.get(core.properties.requires) ?? [];
    if (
      resource.error ||
      !Array.isArray(requires) ||
      requires.some(
        p => p !== core.properties.name && p !== properties['work-source-id'],
      )
    )
      return [];
  }
  for (const definition of spec.properties) {
    const subject = properties[definition.shortname];
    if (!subject) return [];
    const property = await store.getResource(subject);
    const target =
      definition.shortname === 'work-project' ||
      definition.shortname === 'work-person'
        ? classes[definition.shortname]
        : undefined;
    const constraint = property.get(core.properties.classtype);
    if (constraint && target && constraint !== target) return [];
    if (
      property.error ||
      property.get(core.properties.datatype) !== definition.datatype
    )
      return [];
  }
  const subjects = await readConnectionSubjects(
    store,
    drive,
    core.properties.isA,
    dataBrowser.classes.table,
  );
  const tables: TimeTableTarget[] = [];
  for (const subject of subjects) {
    const table = await store.getResource(subject);
    const classSubject = table.get(core.properties.classtype);
    if (table.error || typeof classSubject !== 'string') continue;
    const row = await store.getResource(classSubject);
    if (row.error) continue;
    const requires = row.get(core.properties.requires) ?? [];
    const recommends = row.get(core.properties.recommends) ?? [];
    if (!Array.isArray(requires) || !Array.isArray(recommends)) continue;
    const fields = [...requires, ...recommends];
    if (
      requires.some(p => !supplied.includes(p as string)) ||
      !mapped.every(key => fields.includes(properties[key]!))
    )
      continue;
    tables.push({
      tableSubject: subject,
      classSubject,
      name: table.title,
      schema: { properties, classes },
    });
  }
  return tables.sort((a, b) => a.name.localeCompare(b.name));
}
