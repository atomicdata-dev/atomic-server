import { isJSONObject, type AtomicValue, type Resource } from '@tomic/react';

export interface AtomicDiff {
  oldResource?: Resource;
  newResource: Resource;
  changedProps: string[];
}

export function isPropEqual(
  oldProp: AtomicValue,
  newProp: AtomicValue,
): boolean {
  if (oldProp instanceof Uint8Array && newProp instanceof Uint8Array) {
    if (oldProp.length !== newProp.length) return false;

    for (let i = 0; i < oldProp.length; i++) {
      if (oldProp[i] !== newProp[i]) return false;
    }

    return true;
  }

  if (oldProp instanceof Uint8Array || newProp instanceof Uint8Array) {
    return false;
  }

  if (isJSONObject(oldProp) && isJSONObject(newProp)) {
    return JSON.stringify(oldProp) === JSON.stringify(newProp);
  }

  if (Array.isArray(oldProp) && Array.isArray(newProp)) {
    return JSON.stringify(oldProp) === JSON.stringify(newProp);
  }

  return oldProp === newProp;
}

export function getChangedProps(
  oldResource: Resource | undefined,
  newResource: Resource,
): string[] {
  const changedProps: string[] = [];

  if (!oldResource) {
    return newResource
      .getEntries()
      .map(([key]) => key)
      .filter(key => !key.includes('loroUpdate'));
  }

  for (const [key, value] of oldResource.getEntries()) {
    if (key.includes('loroUpdate')) continue;

    if (!isPropEqual(value, newResource.get(key))) {
      changedProps.push(key);
    }
  }

  for (const [key] of newResource.getEntries()) {
    if (key.includes('loroUpdate')) continue;

    if (oldResource.get(key) === undefined) {
      changedProps.push(key);
    }
  }

  return changedProps;
}

export function useResourceDiff(
  oldResource: Resource | undefined,
  newResource: Resource,
): AtomicDiff {
  const changedProps = getChangedProps(oldResource, newResource);

  return {
    oldResource,
    newResource,
    changedProps,
  };
}
