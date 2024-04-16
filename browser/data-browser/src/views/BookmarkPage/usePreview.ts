import { AtomicError, ErrorType } from './../../../../lib/src/error';
import { Resource, urls, useStore, useString } from '@tomic/react';
import { startTransition, useCallback, useEffect, useState } from 'react';
import { debounce } from '../../helpers/debounce';
import { paths } from '../../routes/paths';

type UsePreviewReturnType = {
  preview?: string;
  /** Call this to update the website URL */
  update: (websiteURL: string) => void;
  error?: Error;
  loading: boolean;
};

async function fetchBookmarkData(url: string, name = '', baseUrl: string) {
  const bookmarkRoute = new URL(paths.fetchBookmark, baseUrl);

  const searchParams = new URLSearchParams({
    name,
    url,
  });

  bookmarkRoute.search = searchParams.toString();

  const res = await fetch(bookmarkRoute.toString(), {
    headers: {
      Accept: 'application/json',
    },
  });

  if (res.status !== 200) {
    throw new AtomicError(await res.text(), ErrorType.Server);
  }

  return await res.json();
}

type Setter<T> = React.Dispatch<React.SetStateAction<T>>;
type AtomicSetter<T> = (val: T) => Promise<void>;

const debouncedFetch = debounce(
  (
    url: string,
    name: string | undefined,
    baseUrl: string,
    resource: Resource,
    setPreview: AtomicSetter<string>,
    setName: AtomicSetter<string>,
    setError: Setter<Error | undefined>,
    setLoading: Setter<boolean>,
    setImageUrl: AtomicSetter<string | undefined>,
    setDescription: AtomicSetter<string | undefined>,
  ) => {
    startTransition(() => {
      fetchBookmarkData(url, name, baseUrl)
        .then(async res => {
          await Promise.all([
            setPreview(res.preview),
            setName(res.name),
            setImageUrl(res['image-url']),
            setDescription(res.description),
          ]);

          setError(undefined);
          setLoading(false);
          resource.save();
        })
        .catch(err => {
          console.error(err);
          setError(err);
          setLoading(false);
        });
    });
  },
);

export function usePreview(resource: Resource): UsePreviewReturnType {
  const store = useStore();
  const [preview, setPreview] = useString(
    resource,
    urls.properties.bookmark.preview,
  );

  const [url] = useString(resource, urls.properties.bookmark.url);
  const [name, setName] = useString(resource, urls.properties.name);
  const [_, setImageUrl] = useString(
    resource,
    urls.properties.bookmark.imageUrl,
  );
  const [__, setDescription] = useString(resource, urls.properties.description);

  const [error, setHasError] = useState<Error | undefined>(undefined);
  const [loading, setLoading] = useState<boolean>(false);

  const update = useCallback(
    (websiteURL: string) => {
      try {
        new URL(websiteURL);
      } catch (e) {
        setHasError(e);

        return;
      }

      setLoading(true);

      debouncedFetch(
        websiteURL,
        name,
        store.getServerUrl(),
        resource,
        setPreview,
        setName,
        setHasError,
        setLoading,
        setImageUrl,
        setDescription,
      );
    },
    [name, resource, store],
  );

  useEffect(() => {
    if (resource.isReady() && preview === undefined && url) {
      update(url);
    }
  }, [preview, resource.isReady()]);

  return { preview, error, update, loading };
}
