import { Resource, Version } from '@tomic/react';

const groupFormatter = new Intl.DateTimeFormat('default', {
  month: 'long',
  year: 'numeric',
});

export function dedupeVersions(versions: Version[]): Version[] {
  const filtered: Version[] = [];
  let v: Version;
  let prev: Version;

  for (let i = 0; i < versions.length; i++) {
    v = versions[i];

    if (i === 0) {
      filtered.push(v);
      continue;
    }

    prev = versions[i - 1];

    if (v.commit.signer !== prev.commit.signer) {
      filtered.push(v);
      continue;
    }

    if (compareMaps(v.resource.getPropVals(), prev.resource.getPropVals())) {
      continue;
    }

    filtered.push(v);
  }

  return filtered;
}

export async function setResourceToVersion(
  resource: Resource,
  version: Version,
): Promise<void> {
  const versionPropvals = version.resource.getPropVals();

  // Remove any prop that doesn't exist in the version
  for (const prop of resource.getPropVals().keys()) {
    if (!versionPropvals.has(prop)) {
      resource.removePropVal(prop);
    }
  }

  for (const [key, value] of versionPropvals.entries()) {
    await resource.set(key, value);
  }

  await resource.save();
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

function compareMaps(map1: Map<string, unknown>, map2: Map<string, unknown>) {
  // Reassigning to testVal uses less memory than redeclaring using const.
  let testVal: unknown;

  if (map1.size !== map2.size) {
    return false;
  }

  for (const [key, val] of map1) {
    testVal = map2.get(key);

    // in cases of an undefined value, make sure the key
    // actually exists on the object so there are no false positives
    if (testVal !== val || (testVal === undefined && !map2.has(key))) {
      if (
        Array.isArray(val) &&
        JSON.stringify(val) === JSON.stringify(testVal)
      ) {
        continue;
      }

      return false;
    }
  }

  return true;
}
