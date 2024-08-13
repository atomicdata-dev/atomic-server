import { type Resource, type Store } from '@tomic/react';

export async function sortSubjectList(
  store: Store,
  subjectList: string[],
): Promise<string[]> {
  const resources: Resource[] = [];

  for (const subject of subjectList) {
    resources.push(await store.getResource(subject));
  }

  resources.sort((a, b) => a.title.localeCompare(b.title));

  return resources.map(r => r.subject);
}
