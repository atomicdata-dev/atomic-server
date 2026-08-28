import {
  CollectionBuilder,
  core,
  dataBrowser,
  forms,
  server,
  Store,
  type JSONValue,
} from '@tomic/react';
import { isChoiceField, infoBoxStyle } from '@tomic/form-renderer';
import type {
  FieldOption,
  OptionsSource,
  FieldOptions,
  FieldType,
  FormBlock,
  FormCondition,
  FormDefinition,
  FormPageDefinition,
  FormStyling,
} from '@tomic/form-renderer';
import { parseStylingValue } from './SettingsTab';
import { parseFieldOptions } from './FieldOptions/useFieldOptions';
import { OPTIONS_SOURCE_KEY } from './FieldOptions/optionsSource';

/**
 * Client-side mirror of `atomic_lib::forms::build_form_definition`
 * (`lib/src/forms.rs`) — walks the same Form -> form-pages -> FormPage ->
 * form-fields graph and produces the identical denormalized shape, so the
 * builder's preview mode (@tomic/form-renderer) renders exactly what
 * `GET /form/:id/definition` would serve once published. `id` is left empty
 * — previews never mint a publish slug.
 */
export async function buildFormDefinitionClientSide(
  store: Store,
  formSubject: string,
): Promise<FormDefinition> {
  const form = await store.getResource(formSubject);

  const name = (form.get(core.properties.name) as string | undefined) ?? '';
  const settings =
    (form.get(forms.properties.formSettings) as
      | Record<string, unknown>
      | undefined) ?? {};

  const pageSubjects =
    (form.get(forms.properties.formPages) as string[] | undefined) ?? [];

  const pages: FormPageDefinition[] = [];

  for (const pageSubject of pageSubjects) {
    pages.push(await buildPageDefinition(store, pageSubject));
  }

  return {
    version: 1,
    id: '',
    name,
    settings,
    styling: await buildStyling(store, form),
    honeypotField: 'hp',
    pages,
  };
}

/** Mirrors `build_form_styling` (server/src/forms.rs), except `imageUrl`:
 * the server points it at the publish-gated `/form/{id}/image` route for
 * anonymous visitors, while this preview uses the File's own `downloadURL`
 * (the owner is authenticated, so the rights-checked route works). */
async function buildStyling(
  store: Store,
  form: Awaited<ReturnType<Store['getResource']>>,
): Promise<FormStyling> {
  // Tolerates the raw-JSON-string form (see parseStylingValue's docs).
  const stylingJson = parseStylingValue(
    form.get(forms.properties.formStyling) as JSONValue | undefined,
  );

  const styling: FormStyling = {
    textColor: stylingJson.textColor as string | undefined,
    mainColor: stylingJson.mainColor as string | undefined,
    backgroundColor: stylingJson.backgroundColor as string | undefined,
    roundness: stylingJson.roundness as string | undefined,
    showProgressBar: stylingJson.showProgressBar as boolean | undefined,
    animatePageTransitions: stylingJson.animatePageTransitions as
      | boolean
      | undefined,
  };

  const coverImage = form.get(forms.properties.coverImage) as
    | string
    | undefined;

  if (coverImage) {
    const file = await store.getResource(coverImage);
    styling.imageUrl = file.get(server.properties.downloadUrl) as
      | string
      | undefined;
    styling.imagePosition = form.get(forms.properties.imagePosition) as
      | string
      | undefined;
  }

  return styling;
}

async function buildPageDefinition(
  store: Store,
  pageSubject: string,
): Promise<FormPageDefinition> {
  const page = await store.getResource(pageSubject);

  const name = page.get(core.properties.name) as string | undefined;
  const coverImage = page.get(forms.properties.coverImage) as
    | string
    | undefined;
  const imagePosition = page.get(forms.properties.imagePosition) as
    | string
    | undefined;

  const fieldSubjects =
    (page.get(forms.properties.formFields) as string[] | undefined) ?? [];

  const blocks: FormBlock[] = [];

  for (const fieldSubject of fieldSubjects) {
    const field = await store.getResource(fieldSubject);
    blocks.push(await buildBlock(store, field));
  }

  const conditions = await buildConditions(store, page);

  return {
    name,
    coverImage,
    imagePosition,
    ...(conditions.length > 0 ? { conditions } : {}),
    blocks,
  };
}

async function buildConditions(
  store: Store,
  resource: Awaited<ReturnType<Store['getResource']>>,
): Promise<FormCondition[]> {
  const subjects =
    (resource.get(forms.properties.formConditions) as string[] | undefined) ??
    [];
  const out: FormCondition[] = [];

  for (const subject of subjects) {
    const cond = await store.getResource(subject);
    const fieldSubject = cond.get(forms.properties.formConditionField) as
      | string
      | undefined;
    let mapsTo = '';

    if (fieldSubject) {
      const field = await store.getResource(fieldSubject);
      mapsTo =
        (field.get(forms.properties.formMapsTo) as string | undefined) ?? '';
    }

    out.push({
      field: mapsTo,
      operator:
        (cond.get(forms.properties.formConditionOperator) as
          | string
          | undefined) ?? 'equals',
      value: parseConditionValue(
        cond.get(forms.properties.formConditionValue) as JSONValue | undefined,
      ),
    });
  }

  return out;
}

function parseConditionValue(raw: JSONValue | undefined): unknown {
  if (raw === undefined || raw === null) return null;

  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  return raw;
}

async function buildBlock(
  store: Store,
  field: Awaited<ReturnType<Store['getResource']>>,
): Promise<FormBlock> {
  const conditions = await buildConditions(store, field);

  if (field.hasClasses(forms.classes.formHeading)) {
    return {
      kind: 'heading',
      text: (field.get(core.properties.name) as string) ?? '',
      ...(conditions.length > 0 ? { conditions } : {}),
    };
  }

  if (field.hasClasses(forms.classes.formInfoBox)) {
    const title = field.get(core.properties.name) as string | undefined;

    return {
      kind: 'info-box',
      // An untitled box is a styled paragraph — don't emit an empty title.
      ...(title ? { title } : {}),
      text: (field.get(core.properties.description) as string) ?? '',
      style: infoBoxStyle(
        field.get(forms.properties.formInfoBoxStyle) as string | undefined,
      ),
      ...(conditions.length > 0 ? { conditions } : {}),
    };
  }

  if (field.hasClasses(forms.classes.formParagraph)) {
    return {
      kind: 'paragraph',
      text: (field.get(core.properties.description) as string) ?? '',
      ...(conditions.length > 0 ? { conditions } : {}),
    };
  }

  const mapsTo = (field.get(forms.properties.formMapsTo) as string) ?? '';
  const type =
    (field.get(forms.properties.formFieldType) as FieldType | undefined) ??
    'short-text';

  const options = (await resolveChoiceOptions(
    store,
    type,
    mapsTo,
    parseFieldOptions(
      field.get(forms.properties.formFieldOptions) as JSONValue | undefined,
    ),
  )) as FieldOptions;

  return {
    kind: 'field',
    mapsTo,
    label: (field.get(core.properties.name) as string) ?? '',
    description: field.get(core.properties.description) as string | undefined,
    type,
    required: Boolean(field.get(forms.properties.required)),
    options,
    ...(conditions.length > 0 ? { conditions } : {}),
  };
}

/**
 * Mirrors `resolve_choice_options` (server/src/forms.rs): a choice question's
 * options resolved into inline option objects, from wherever its
 * `optionsSource` points — by default the Tags on its own mapped Property's
 * `allowsOnly`.
 *
 * One deliberate difference, the same split as the cover image in
 * `buildStyling`: a `picture-choice` option's image is a File subject, which
 * the server rewrites into a publish-gated `/form/{id}/image?file=…` URL for
 * agent-less visitors (`fill_image_url`). The preview uses the File's own
 * `downloadURL` instead, since the builder is authenticated.
 */
async function resolveChoiceOptions(
  store: Store,
  type: FieldType,
  mapsTo: string,
  options: Record<string, JSONValue>,
): Promise<Record<string, JSONValue>> {
  if (!isChoiceField(type)) {
    return options;
  }

  const source = (options[OPTIONS_SOURCE_KEY] ?? {}) as OptionsSource;

  let resolved: FieldOption[];

  if (source.property) {
    resolved = await tagOptions(store, source.property);
  } else if (source.table) {
    resolved = await rowOptions(store, source.table, source.labelProperty);
  } else if (mapsTo) {
    resolved = await tagOptions(store, mapsTo);
  } else {
    return options;
  }

  return { ...options, options: resolved as unknown as JSONValue };
}

const nonEmpty = (value: unknown) =>
  typeof value === 'string' && value !== '' ? value : undefined;

/** Mirrors `tag_options` (server/src/forms.rs). */
async function tagOptions(
  store: Store,
  propertySubject: string,
): Promise<FieldOption[]> {
  const property = await store.getResource(propertySubject);
  const tagSubjects =
    (property.get(core.properties.allowsOnly) as string[] | undefined) ?? [];

  return Promise.all(
    tagSubjects.map(async subject =>
      buildOption(store, await store.getResource(subject), subject),
    ),
  );
}

/**
 * Mirrors `row_options` (server/src/forms.rs): every row of the table becomes
 * an option whose `value` is the row's subject, labelled by `labelProperty`.
 *
 * The row query is the same `parent` + `isA` pair the server uses (and
 * `DeleteFormDialog`, and `useSubmissionCount`). No cap here, unlike the
 * server's `OPTIONS_ROW_LIMIT` — the preview runs against the builder's own
 * drive, and a mismatch shows up as a longer list than the published form
 * offers rather than a shorter one.
 */
async function rowOptions(
  store: Store,
  tableSubject: string,
  labelProperty: string | undefined,
): Promise<FieldOption[]> {
  const table = await store.getResource(tableSubject);
  const rowClass = nonEmpty(table.get(core.properties.classtype));

  if (!rowClass) return [];

  const collection = await new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(tableSubject)
    .setFilters([{ property: core.properties.isA, value: rowClass }])
    .buildAndFetch();

  const out: FieldOption[] = [];

  for await (const rowSubject of collection) {
    const row = await store.getResource(rowSubject);
    const label = labelProperty ? rowLabel(row, labelProperty) : undefined;

    // A row the picked column is empty for is not offered — see `rowLabel`.
    if (labelProperty && label === undefined) continue;

    out.push(await buildOption(store, row, rowSubject, label));
  }

  return out;
}

/**
 * Mirrors `row_label` (server/src/forms.rs): the picked column's value as one
 * line of text, or `undefined` — which means the row is left out of the list
 * entirely rather than labelled from some other column.
 */
function rowLabel(
  row: Awaited<ReturnType<Store['getResource']>>,
  labelProperty: string,
): string | undefined {
  const value = row.get(labelProperty);

  if (typeof value === 'string') return nonEmpty(value.trim());

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  // Arrays and objects (a relation, a nested resource, a JSON blob) have no
  // one-line rendering, so they read as no label at all.
  return undefined;
}

async function buildOption(
  store: Store,
  resource: Awaited<ReturnType<Store['getResource']>>,
  subject: string,
  /** Already-resolved label ({@link rowLabel}); absent for Tags, which title
   * themselves. */
  resolvedLabel?: string,
): Promise<FieldOption> {
  const imageSubject = nonEmpty(resource.get(forms.properties.coverImage));
  const image = imageSubject
    ? ((await store.getResource(imageSubject)).get(
        server.properties.downloadUrl,
      ) as string | undefined)
    : undefined;

  const option: FieldOption = {
    value: subject,
    // Same precedence as `useTitle`: the free-text name, else the slug.
    label:
      resolvedLabel ??
      nonEmpty(resource.get(core.properties.name)) ??
      nonEmpty(resource.get(core.properties.shortname)) ??
      subject,
  };

  const color = nonEmpty(resource.get(dataBrowser.properties.color));
  const emoji = nonEmpty(resource.get(dataBrowser.properties.emoji));

  if (color) option.color = color;

  if (emoji) option.emoji = emoji;

  if (image) option.image = image;

  return option;
}
