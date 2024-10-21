import { env } from '@/env';
import { website } from '@/ontologies/website';
import { CollectionBuilder, core, Store } from '@tomic/lib';

export async function getAllBlogposts(): Promise<string[]> {
  const store = new Store({
    serverUrl: env.NEXT_PUBLIC_ATOMIC_SERVER_URL,
  });

  const collection = new CollectionBuilder(store)
    .setProperty(core.properties.isA)
    .setValue(website.classes.blogpost)
    .setSortBy(website.properties.publishedAt)
    .setSortDesc(true)
    .build();

  return collection.getAllMembers();
}
