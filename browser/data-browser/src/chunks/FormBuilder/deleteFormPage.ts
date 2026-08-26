import { forms, type Resource, type Store } from '@tomic/react';

/**
 * Removes a page from a form and destroys it, along with its conditions.
 *
 * The form is pointed away from the page BEFORE anything is destroyed, and
 * that commit is awaited — the reverse order leaves the form referencing a
 * destroyed page if the debounced commit never lands.
 *
 * Never removes the last page: a form without pages has nowhere to put
 * fields.
 */
export async function deleteFormPage(
  store: Store,
  formResource: Resource,
  pages: string[],
  subject: string,
): Promise<void> {
  if (pages.length <= 1) {
    return;
  }

  const remaining = pages.filter(p => p !== subject);

  await formResource.set(forms.properties.formPages, remaining);
  await formResource.save();

  const page = await store.getResource(subject);
  const conditions =
    (page.get(forms.properties.formConditions) as string[] | undefined) ?? [];

  for (const condSubject of conditions) {
    const cond = await store.getResource(condSubject);
    await cond.destroy();
  }

  await page.destroy();
}
