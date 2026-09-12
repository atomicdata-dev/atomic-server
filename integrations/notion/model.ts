// @wc-ignore-file
/** Pure Notion mapping. Unsupported values fail closed; writes patch mapped fields only. */
import type {
  ExternalIntent,
  ExternalReceipt,
} from '../../browser/lib/src/plugin-connection.js';
export const API_VERSION = '2026-03-11';
export const base = 'https://api.notion.com/v1';
export const P = {
  name: 'https://atomicdata.dev/properties/name',
  parent: 'https://atomicdata.dev/properties/parent',
  isA: 'https://atomicdata.dev/properties/isA',
  columns: 'https://atomicdata.dev/properties/view-columns',
  kind: 'https://atomicdata.dev/properties/view-kind',
  group: 'https://atomicdata.dev/properties/view-group-by',
};
export const types = [
  'title',
  'rich_text',
  'number',
  'checkbox',
  'url',
  'email',
  'phone_number',
  'select',
  'multi_select',
  'status',
] as const;
export type FieldType = (typeof types)[number];
export interface Field {
  id: string;
  property: string;
  type: FieldType;
  options?: Record<string, string>;
  optionNames?: Record<string, string>;
}
export interface ViewBinding {
  id: string;
  subject: string;
  kind: 'table' | 'board';
}
export interface Config {
  dataSource: string;
  table: string;
  rowClass: string;
  identity: string;
  arrival: string;
  fields: Field[];
  views: ViewBinding[];
}
export type Projection = Record<
  string,
  string | number | boolean | null | string[]
>;
export function equal(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (
    !a ||
    !b ||
    typeof a !== 'object' ||
    typeof b !== 'object' ||
    Array.isArray(a) !== Array.isArray(b)
  )
    return false;
  const x = a as Record<string, unknown>,
    y = b as Record<string, unknown>;
  return (
    Object.keys(x).length === Object.keys(y).length &&
    Object.keys(x).every(k => Object.hasOwn(y, k) && equal(x[k], y[k]))
  );
}
export function uuid(value: string): string {
  if (
    !/^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.test(
      value,
    )
  )
    throw new Error('Expected a Notion data source/page/view UUID');
  const s = value.replaceAll('-', '').toLowerCase();
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
}
export function manifest(dataSource: string) {
  const id = uuid(dataSource);
  return {
    schemaVersion: 1,
    secrets: [
      {
        name: 'notion',
        origin: 'https://api.notion.com',
        description: 'Notion connection shared with this data source',
      },
    ],
    operations: [
      {
        id: 'schema',
        method: 'GET',
        url: `${base}/data_sources/${id}`,
        effect: 'read',
      },
      {
        id: 'rename',
        method: 'PATCH',
        url: `${base}/data_sources/${id}`,
        effect: 'write',
      },
      {
        id: 'query',
        method: 'POST',
        url: `${base}/data_sources/${id}/query`,
        effect: 'read',
      },
      {
        id: 'page',
        method: 'GET',
        url: `${base}/pages/{uuid}`,
        effect: 'read',
      },
      { id: 'create', method: 'POST', url: `${base}/pages`, effect: 'write' },
      {
        id: 'update',
        method: 'PATCH',
        url: `${base}/pages/{uuid}`,
        effect: 'write',
      },
      { id: 'views', method: 'GET', url: `${base}/views`, effect: 'read' },
      {
        id: 'view',
        method: 'GET',
        url: `${base}/views/{uuid}`,
        effect: 'read',
      },
      {
        id: 'view-update',
        method: 'PATCH',
        url: `${base}/views/{uuid}`,
        effect: 'write',
      },
    ],
  };
}
export function request(
  operation: string,
  method: string,
  path: string,
  body?: unknown,
  id = operation,
): ExternalIntent {
  return {
    id,
    operation,
    method,
    url: base + path,
    headers: {
      Authorization: 'secret:notion',
      'Notion-Version': API_VERSION,
      'Content-Type': 'application/json',
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}
export function parse(receipt: ExternalReceipt): any {
  if (receipt.status < 200 || receipt.status >= 300)
    throw new Error(
      `Notion returned ${receipt.status}; sync paused, no deletion inferred`,
    );
  return JSON.parse(receipt.body);
}
export function plainText(parts: any): string {
  if (!Array.isArray(parts)) throw new Error('Invalid Notion text');
  let text = '';
  for (const p of parts) {
    if (
      p.type !== 'text' ||
      typeof p.text?.content !== 'string' ||
      p.text.link ||
      (p.annotations &&
        Object.entries(p.annotations).some(([k, v]) =>
          k === 'color' ? v !== 'default' : v !== false,
        ))
    )
      throw new Error(
        'Formatted text or mentions need a lossless mapping; this field cannot sync as plain text',
      );
    text += p.text.content;
  }
  return text;
}
export function validateValue(field: Field, value: any): void {
  const t = field.type;
  if (
    t === 'number'
      ? value !== null && (typeof value !== 'number' || !Number.isFinite(value))
      : t === 'checkbox'
        ? typeof value !== 'boolean'
        : t === 'multi_select'
          ? !Array.isArray(value) ||
            value.some(
              (id: any) => typeof id !== 'string' || !field.options?.[id],
            )
          : t === 'select' || t === 'status'
            ? value !== null &&
              (typeof value !== 'string' || !field.options?.[value])
            : value !== null && typeof value !== 'string'
  )
    throw new Error(`Invalid or unmapped ${t} value for property ${field.id}`);
  if ((t === 'title' || t === 'rich_text') && typeof value !== 'string')
    throw new Error('Text must be a string');
}
export function projectPage(page: any, c: Config): Projection {
  if (
    page.object !== 'page' ||
    uuid(page.parent?.data_source_id ?? '') !== uuid(c.dataSource) ||
    page.archived ||
    page.in_trash
  )
    throw new Error(
      'Page missing, moved, archived or outside the connected data source; reconcile explicitly',
    );
  const byId = new Map(
    Object.values(page.properties ?? {}).map((v: any) => [v.id, v]),
  );
  const result: Projection = {};
  for (const f of c.fields) {
    const p: any = byId.get(f.id);
    if (!p || p.type !== f.type)
      throw new Error(`Mapped property ${f.id} is missing or changed type`);
    const raw = p[f.type];
    const v =
      f.type === 'title' || f.type === 'rich_text'
        ? plainText(raw)
        : f.type === 'multi_select'
          ? raw.map((o: any) => o.id).sort()
          : f.type === 'select' || f.type === 'status'
            ? (raw?.id ?? null)
            : raw;
    validateValue(f, v);
    result[f.id] = v;
  }
  return result;
}
export function projectRow(
  row: Record<string, any>,
  c: Config,
  baseline?: Projection,
): Projection {
  if (row[P.parent] !== c.table || !row[P.isA]?.includes(c.rowClass))
    throw new Error('Atomic row moved or changed class');
  const result: Projection = {};
  for (const f of c.fields) {
    let v = row[f.property];
    if (f.type === 'title' && f.property !== P.name) {
      const display = row[P.name];
      if (v === undefined) v = display;
      else if (display !== undefined && v !== display) {
        if (baseline && v === baseline[f.id]) v = display;
        else if (!baseline || display !== baseline[f.id])
          throw new Error(
            'Title and display name changed independently; resolve the local conflict',
          );
      }
    }
    if (f.options) {
      if (!Array.isArray(v ?? []))
        throw new Error('Select values must be Atomic tag arrays');
      const ids = (v ?? [])
        .map((tag: string) => {
          const id = Object.entries(f.options!).find(([, p]) => p === tag)?.[0];
          if (!id) throw new Error('Unmapped Atomic select option');
          return id;
        })
        .sort();
      if (f.type !== 'multi_select' && ids.length > 1)
        throw new Error('Select/status supports at most one option');
      v = f.type === 'multi_select' ? ids : (ids[0] ?? null);
    } else
      v ??=
        f.type === 'checkbox'
          ? false
          : f.type === 'title' || f.type === 'rich_text'
            ? ''
            : null;
    validateValue(f, v);
    result[f.id] = v;
  }
  return result;
}
export function pagePatch(
  desired: Projection,
  previous: Projection | undefined,
  c: Config,
): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  for (const f of c.fields) {
    const value = desired[f.id];
    validateValue(f, value);
    if (previous && equal(previous[f.id], value)) continue;
    let encoded: unknown = value;
    if (f.type === 'title' || f.type === 'rich_text') {
      // Each Notion text object is limited to 2000 characters; never truncate.
      const text = value as string;
      const parts = [];
      for (let i = 0; i < text.length; ) {
        let end = Math.min(i + 2000, text.length);
        if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1])) end--;
        parts.push({ type: 'text', text: { content: text.slice(i, end) } });
        i = end;
      }
      if (parts.length > 100)
        throw new Error("Text exceeds Notion's block-array limit");
      encoded = parts;
    } else if (f.type === 'multi_select')
      encoded = (value as string[]).map(id => ({ id }));
    else if (f.type === 'select' || f.type === 'status')
      encoded = value === null ? null : { id: value };
    properties[f.id] = { [f.type]: encoded };
  }
  return properties;
}
export function rowPatch(
  desired: Projection,
  c: Config,
): { set: Record<string, unknown>; remove: string[] } {
  const set: Record<string, unknown> = {};
  const remove: string[] = [];
  for (const f of c.fields) {
    const v = desired[f.id];
    validateValue(f, v);
    if (f.options)
      set[f.property] =
        f.type === 'multi_select'
          ? (v as string[]).map(id => f.options![id])
          : v === null
            ? []
            : [f.options[v as string]];
    else if (v === null) remove.push(f.property);
    else set[f.property] = v;
  }
  const title = c.fields.find(f => f.type === 'title');
  if (title) set[P.name] = desired[title.id];
  return { set, remove };
}
/** Conservative first subset: don't render a filtered Notion view as unfiltered Atomic. */
export function projectView(view: any, c: Config): Projection {
  if (
    uuid(view.data_source_id ?? '') !== uuid(c.dataSource) ||
    !['table', 'board'].includes(view.type)
  )
    throw new Error('Unsupported view type or foreign data source');
  if (
    view.filter ||
    view.sorts?.length ||
    Object.keys(view.quick_filters ?? {}).length
  )
    throw new Error(
      'View filters/sorts need a lossless mapping; view not imported',
    );
  const cfg = view.configuration ?? {};
  if (
    (cfg.subtasks && cfg.subtasks.display_mode !== 'disabled') ||
    cfg.sub_group_by
  )
    throw new Error('View subtasks/subgroups are not mapped');
  const columns = (
    cfg.properties ?? c.fields.map(f => ({ property_id: f.id, visible: true }))
  )
    .filter((p: any) => p.visible !== false)
    .map((p: any) => p.property_id);
  if (columns.some((id: string) => !c.fields.some(f => f.id === id)))
    throw new Error('View contains unmapped visible properties');
  if (cfg.group_by?.type === 'status' && cfg.group_by.group_by !== 'option')
    throw new Error('Status groups are not individual Atomic kanban options');
  if (!columns.length)
    throw new Error('A connected view needs visible columns');
  const group = cfg.group_by?.property_id ?? null;
  if (group && !c.fields.find(f => f.id === group)?.options)
    throw new Error('View grouping must use a mapped select/status property');
  if (view.type === 'board' && !group)
    throw new Error('Board requires an explicit mapped grouping property');
  // Table grouping is not the same renderer as kanban grouping.
  if (view.type === 'table' && group)
    throw new Error('Grouped table views are not mapped yet');
  return { name: view.name, columns, group, kind: view.type };
}
export function projectLocalView(
  row: Record<string, any>,
  c: Config,
  binding: ViewBinding,
): Projection {
  if (
    row['https://atomicdata.dev/properties/view-filters']?.length ||
    row['https://atomicdata.dev/properties/view-sort-by']
  )
    throw new Error('Connected view filters/sorts are not mapped yet');
  const kind = row[P.kind] === 'kanban' ? 'board' : row[P.kind];
  if (kind !== binding.kind)
    throw new Error('Changing a connected view type is not supported');
  const find = (subject: string) => {
    const f = c.fields.find(f => f.property === subject);
    if (!f) throw new Error('View uses an unmapped Atomic property');
    return f.id;
  };
  const columns = (row[P.columns] ?? []).map(find);
  if (!columns.length)
    throw new Error('Connected view requires explicit visible columns');
  return {
    name: row[P.name],
    columns,
    group: row[P.group] ? find(row[P.group]) : null,
    kind,
  };
}
export function viewPatch(desired: Projection, current: any, c: Config): any {
  const before = projectView(current, c);
  const patch: any = {};
  if (desired.name !== before.name) patch.name = desired.name;
  if (
    !equal(desired.columns, before.columns) ||
    desired.group !== before.group
  ) {
    // Preserve provider-only widths/covers/etc instead of rebuilding configuration.
    const cfg = { ...current.configuration };
    const ids = desired.columns as string[];
    const existing = cfg.properties ?? [];
    cfg.properties = [
      ...ids.map(id => ({
        ...existing.find((p: any) => p.property_id === id),
        property_id: id,
        visible: true,
      })),
      ...existing
        .filter((p: any) => !ids.includes(p.property_id))
        .map((p: any) => ({ ...p, visible: false })),
    ];
    if (desired.group !== before.group) {
      const f = c.fields.find(f => f.id === desired.group);
      if (!f?.options || desired.kind !== 'board')
        throw new Error('Unsupported view grouping change');
      // Existing group ordering is specific to the original property: do not reuse it.
      cfg.group_by = {
        type: f.type,
        property_id: f.id,
        sort: { type: 'manual' },
        ...(f.type === 'status' ? { group_by: 'option' } : {}),
      };
    }
    patch.configuration = cfg;
  }
  return patch;
}
