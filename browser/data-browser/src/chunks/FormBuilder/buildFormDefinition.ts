import { core, forms, Store, type JSONValue } from '@tomic/react';
import type {
  FieldOptions,
  FieldType,
  FormBlock,
  FormDefinition,
  FormPageDefinition,
} from '@tomic/form-renderer';

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
    honeypotField: 'hp',
    pages,
  };
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
