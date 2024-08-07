import {
  type FetchOpts,
  type OptionalClass,
  Resource,
  Store,
} from '@tomic/lib';

import { type Readable, get, readable, type Subscriber } from 'svelte/store';
import { store } from './store.js';

const subscribeToADStore = (
  adStore: Store,
  subject: string,
  set: Subscriber<Resource>,
  opts?: FetchOpts,
) => {
  set(adStore.getResourceLoading(subject, opts));

  const subscriber = (changedResource: Resource) => {
    set(changedResource);
  };

  adStore.subscribe(subject, subscriber);

  return () => {
    adStore.unsubscribe(subject, subscriber);
  };
};

/**
 * Gets a resource from the store. The resource might still be loading, use `resource.loading` to make sure it is ready.
 * If you've generated types using @tomic/cli, you can pass the class as a Generic to get type checking on the resource.
 */
export const getResource = <C extends OptionalClass = never>(
  subject: string | Readable<string>,
  opts?: FetchOpts,
): Readable<Resource<C>> => {
  const adStore = get(store);

  const subjectValue = typeof subject === 'string' ? subject : get(subject);

  // eslint-disable-next-line prefer-const
  let resource = readable<Resource<C>>(
    adStore.getResourceLoading(subjectValue, opts),
    set => {
      if (typeof subject !== 'string') {
        let atomicUnsubscriber: () => void;

        const subjectUnsubscriber = subject.subscribe(value => {
          atomicUnsubscriber?.();

          set(adStore.getResourceLoading(value, opts));
          atomicUnsubscriber = subscribeToADStore(adStore, value, set, opts);
        });

        return () => {
          subjectUnsubscriber();
          atomicUnsubscriber?.();
        };
      } else {
        return subscribeToADStore(adStore, subject, set, opts);
      }
    },
  );

  return resource;
};
