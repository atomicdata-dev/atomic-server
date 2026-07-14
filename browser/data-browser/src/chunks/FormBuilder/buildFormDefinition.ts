import { core, forms, server, Store, type JSONValue } from '@tomic/react';
import type {
  FieldOptions,
  FieldType,
  FormBlock,
  FormDefinition,
  FormPageDefinition,
  FormStyling,
} from '@tomic/form-renderer';
import { parseStylingValue } from './SettingsTab';

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
    blocks.push(buildBlock(field));
  }

  return { name, coverImage, imagePosition, blocks };
}

function buildBlock(
  field: Awaited<ReturnType<Store['getResource']>>,
): FormBlock {
  if (field.hasClasses(forms.classes.formHeading)) {
    return {
      kind: 'heading',
      text: (field.get(core.properties.name) as string) ?? '',
    };
  }

  if (field.hasClasses(forms.classes.formParagraph)) {
    return {
      kind: 'paragraph',
      text: (field.get(core.properties.description) as string) ?? '',
    };
  }

  const options =
    (field.get(forms.properties.formFieldOptions) as JSONValue as
      | FieldOptions
      | undefined) ?? {};

  return {
    kind: 'field',
    mapsTo: (field.get(forms.properties.formMapsTo) as string) ?? '',
    label: (field.get(core.properties.name) as string) ?? '',
    description: field.get(core.properties.description) as string | undefined,
    type:
      (field.get(forms.properties.formFieldType) as FieldType | undefined) ??
      'short-text',
    required: Boolean(field.get(forms.properties.required)),
    options,
  };
}
