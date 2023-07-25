import { Resource, Store, Version } from '@tomic/react';

const groupFormatter = new Intl.DateTimeFormat('default', {
  month: 'long',
  year: 'numeric',
});

/** Removes back to back duplicate versions */
export function dedupeVersions(versions: Version[]): Version[] {
  return versions.filter((v, i) => {
    if (i === 0) {
      return true;
    }

    const prev = versions[i - 1];

    if (v.commit.signer !== prev.commit.signer) {
      return true;
    }

    return resourceToString(v.resource) !== resourceToString(prev.resource);
  });
}

export async function setResourceToVersion(
  resource: Resource,
  version: Version,
  store: Store,
): Promise<void> {
  const versionPropvals = version.resource.getPropVals();

  // Remove any prop that doesn't exist in the version
  for (const prop of resource.getPropVals().keys()) {
    if (!versionPropvals.has(prop)) {
      resource.removePropVal(prop);
    }
  }

  for (const [key, value] of versionPropvals.entries()) {
    await resource.set(key, value, store);
  }

  await resource.save(store);
}

export function groupVersionsByMonth(
  versions: Version[],
): Record<string, Version[]> {
  return versions.reduceRight((acc, version) => {
    const createdDate = new Date(version.commit.createdAt);
    const groupKey = groupFormatter.format(createdDate);
    const group = acc[groupKey] ?? [];

    return {
      ...acc,
      [groupKey]: [...group, version],
    };
  }, {});
}

function resourceToString(resource: Resource) {
  const obj = {};

  for (const [key, value] of resource.getPropVals().entries()) {
    obj[key] = value;
  }

  return JSON.stringify(obj);
}
