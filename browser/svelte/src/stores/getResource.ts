import { type FetchOpts, Resource, Store } from '@tomic/lib';

import { type Readable, get, readable, Subscriber } from 'svelte/store';
import { store } from './store';

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

export const getResource = (
  subject: string | Readable<string>,
  opts?: FetchOpts,
): Readable<Resource> => {
  const adStore = get(store);

  const subjectValue = typeof subject === 'string' ? subject : get(subject);

  // eslint-disable-next-line prefer-const
  let resource = readable<Resource>(
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
