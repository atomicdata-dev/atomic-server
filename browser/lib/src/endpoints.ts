import { Resource, Store, urls } from './index.js';
/** Endpoints are Resources that can respond to query parameters or POST bodies */

type ImportOpts = {
  /** Where the resources will be imported to  */
  parent: string;
  /** Danger: Replaces Resources with matching subjects, even if they are not Children of the specified Parent. */
  overwriteOutside?: boolean;
};

const addParams = (urlBase: string, params: Record<string, string>) => {
  const parsed = new URL(urlBase);

  for (const [key, val] of Object.entries(params)) {
    parsed.searchParams.set(key, val);
  }

  return parsed.toString();
};

function resourceToErr(resource: Resource) {
  if (resource.error) {
    throw resource.error;
  } else {
    return Resource;
  }
}

/**
 * POSTs a JSON-AD string (containing either an array of Resources or one Resource object) to the Server.
 * See https://docs.atomicdata.dev/create-json-ad.html
 */
export async function importJsonAdString(
  store: Store,
  jsonAdString: string,
  opts: ImportOpts,
) {
  const url = addParams(store.getServerUrl() + urls.endpoints.import, {
    parent: opts.parent,
    'overwrite-outside': opts.overwriteOutside ? 'true' : 'false',
  });

  return resourceToErr(await store.postToServer(url, jsonAdString));
}
