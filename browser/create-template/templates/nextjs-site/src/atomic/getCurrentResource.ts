import { CollectionBuilder, type Resource } from "@tomic/lib";
import { website } from "@/ontologies/website";
import { Store } from "@tomic/lib";
import { env } from "@/env";

/**
 * Queries the server for a resource with a href property that matches the given url pathname.
 * @param url The current URL in the browser.
 * @returns Promise that resolves to the subject of the resource, or undefined if no resource was found.
 */
export async function getCurrentResource(
  url: URL
): Promise<Resource | undefined> {
  const store = new Store({
    serverUrl: env.NEXT_PUBLIC_ATOMIC_SERVER_URL,
  });

  const path = url.pathname;

  // Find the resource with the current path as href.
  const collection = await new CollectionBuilder(store)
    .setProperty(website.properties.href)
    .setValue(path)
    .buildAndFetch();

  if (collection.totalMembers === 0) {
    return undefined;
  }

  const currentResourceSubject = await collection.getMemberWithIndex(0);

  if (!currentResourceSubject) {
    return undefined;
  }

  return await store.getResource(currentResourceSubject);
}
