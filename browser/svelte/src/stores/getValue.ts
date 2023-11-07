import { Resource, JSONValue } from '@tomic/lib';
import { Readable, Writable, get } from 'svelte/store';

import { store } from './store';

export type ValueSubscriber<T extends JSONValue> = (
  value: T | undefined,
) => void;
export type ValueUpdater<T extends JSONValue> = (
  value: T | undefined,
) => T | undefined;

export const getValue = <T extends JSONValue = JSONValue>(
  resourceStore: Readable<Resource>,
  property: string,
  commit = false,
): Writable<T | undefined> => {
  const adStore = get(store);
  let resource: Resource = get(resourceStore);

  let value: T | undefined = resource.get(property) as T;
  const subscriptions = new Set<ValueSubscriber<T>>();
  let subscribedToStore = false;

  const storeSubscriber = (newResource: Resource) => {
    value = newResource.get(property) as T;
    notifySvelteChange();
  };

  const notifySvelteChange = () => {
    for (const subscriber of subscriptions) {
      subscriber(value);
    }
  };

  const setValue = async (val: T | undefined) => {
    value = val;

    if (val === undefined) {
      resource.removePropVal(property);
    } else {
      resource.set(property, val, adStore, false);
    }

    if (commit) {
      await resource.save(adStore);
    }

    adStore.addResources(resource);
  };

  const writable = {
    set(val: T): void {
      setValue(val);
      notifySvelteChange();
    },

    subscribe(subscriber: ValueSubscriber<T>): () => void {
      if (!subscribedToStore) {
        adStore.subscribe(resource.getSubject(), storeSubscriber);
        subscribedToStore = true;
      }

      subscriptions.add(subscriber);

      // Call the subscriber to get the value instantly.
      subscriber(value);

      return () => {
        subscriptions.delete(subscriber);

        if (subscriptions.size === 0) {
          adStore.unsubscribe(resource.getSubject(), storeSubscriber);
          subscribedToStore = false;
        }
      };
    },

    update(updater: ValueUpdater<T>): void {
      setValue(updater(value)).then(() => {
        notifySvelteChange();
      });
    },
  };

  resourceStore.subscribe(r => {
    value = r.get(property) as T;
    resource = r;
    notifySvelteChange();
  });

  return writable;
};
