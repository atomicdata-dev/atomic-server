import {
  Resource,
  type InferTypeOfValueInTriple,
  type OptionalClass,
} from '@tomic/lib';
import { type Readable, type Writable, get } from 'svelte/store';

import { store } from './store.js';

export type ValueSubscriber<
  Prop extends string,
  C extends OptionalClass = never,
> = (value: InferTypeOfValueInTriple<C, Prop>) => void;
export type ValueUpdater<
  Prop extends string,
  C extends OptionalClass = never,
> = (
  value: InferTypeOfValueInTriple<C, Prop>,
) => InferTypeOfValueInTriple<C, Prop>;

/**
 * Gets the value of a property on a resource.
 * Returns a writable store.
 * The type of the value is automatically inferred from the property when the resource is marked with a class (using a Generic) and the types were generated using @tomic/cli.
 */
export const getValue = <Prop extends string, C extends OptionalClass = never>(
  resourceStore: Readable<Resource<C>>,
  property: Prop,
  commit = false,
): Writable<InferTypeOfValueInTriple<C, Prop>> => {
  type Returns = InferTypeOfValueInTriple<C, Prop>;

  const adStore = get(store);
  let resource: Resource<C> = get(resourceStore);

  let value = resource.get(property);
  const subscriptions = new Set<ValueSubscriber<Prop, C>>();
  let subscribedToStore = false;

  const storeSubscriber = (newResource: Resource<C>) => {
    value = newResource.get(property);
    notifySvelteChange();
  };

  const notifySvelteChange = () => {
    for (const subscriber of subscriptions) {
      subscriber(value);
    }
  };

  const setValue = async (val: Returns) => {
    value = val;

    if (val === undefined) {
      resource.removePropVal(property);
    } else {
      resource.set(property, val, false);
    }

    if (commit) {
      await resource.save();
    }

    adStore.addResources(resource);
  };

  const writable = {
    set(val: Returns): void {
      setValue(val);
      notifySvelteChange();
    },

    subscribe(subscriber: ValueSubscriber<Prop, C>): () => void {
      if (!subscribedToStore) {
        adStore.subscribe(resource.subject, storeSubscriber);
        subscribedToStore = true;
      }

      subscriptions.add(subscriber);

      // Call the subscriber to get the value instantly.
      subscriber(value);

      return () => {
        subscriptions.delete(subscriber);

        if (subscriptions.size === 0) {
          adStore.unsubscribe(resource.subject, storeSubscriber);
          subscribedToStore = false;
        }
      };
    },

    update(updater: ValueUpdater<Prop, C>): void {
      setValue(updater(value)).then(() => {
        notifySvelteChange();
      });
    },
  };

  resourceStore.subscribe(r => {
    value = r.get(property);
    resource = r;
    notifySvelteChange();
  });

  return writable;
};
