import { core, forms, Resource, Store, CollectionBuilder } from '@tomic/react';

/** Delete only form presentation resources, never mapped columns or Tags. */
export async function deleteForm(store: Store, form: Resource) {
  const destroyConditions = async (resource: Resource) => {
    for (const subject of resource.getSubjects(
      forms.properties.formConditions,
    )) {
      await (await store.getResource(subject)).destroy();
    }
  };

  for (const subject of form.getSubjects(forms.properties.formPages)) {
    const page = await store.getResource(subject);

    for (const fieldSubject of page.getSubjects(forms.properties.formFields)) {
      const field = await store.getResource(fieldSubject);
      await destroyConditions(field);
      await field.destroy();
    }

    await destroyConditions(page);
    await page.destroy();
  }

  await form.destroy();
}

export async function deleteTableForms(store: Store, table: Resource) {
  const collection = await new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(table.subject)
    .setFilters([{ property: core.properties.isA, value: forms.classes.form }])
    .buildAndFetch();
  for await (const subject of collection)
    await deleteForm(store, await store.getResource(subject));
}
