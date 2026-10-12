import {
  hexToBytes,
  isBlobSubject,
  blobHashHex,
  server,
  type Resource,
} from '@tomic/lib';
import { useEffect, useState } from 'react';
import { useStore } from './hooks.js';

const BLOB = 'https://atomicdata.dev/properties/blob';

/**
 * Object URLs already made for a blob, per database, most recently used last.
 *
 * Without this every mount read the bytes out of the database again, returned
 * `undefined` until it finished, and made a brand new `blob:` URL the browser
 * had to decode from scratch, so an avatar on a page you reopen popped in late
 * every time. Kept small because this hook also serves large file previews;
 * the oldest URL is revoked when the list is full.
 */
const MAX_CACHED_URLS = 24;
const urlCache = new WeakMap<object, Map<string, string>>();

function cachedUrl(db: object | undefined, blobDid: string) {
  const entries = db ? urlCache.get(db) : undefined;
  const url = entries?.get(blobDid);

  if (url && entries) {
    // Refresh recency.
    entries.delete(blobDid);
    entries.set(blobDid, url);
  }

  return url;
}

function rememberUrl(db: object, blobDid: string, url: string) {
  let entries = urlCache.get(db);

  if (!entries) {
    entries = new Map();
    urlCache.set(db, entries);
  }

  entries.set(blobDid, url);

  if (entries.size > MAX_CACHED_URLS) {
    const [oldest] = entries.keys();
    const evicted = entries.get(oldest);
    entries.delete(oldest);

    if (evicted) URL.revokeObjectURL(evicted);
  }
}

/**
 * Returns a `blob:` object URL for the file's bytes when they are available
 * locally in the WASM clientDb (e.g. just-uploaded files, or anything cached
 * from a prior session). Waits for the local lookup before returning the
 * optional network fallback. Returns `undefined` while the lookup is pending.
 *
 * Lets the UI preview a freshly-uploaded image even before the bytes have
 * been pushed to the server, and lets it keep working while offline.
 */
export function useFileObjectUrl(
  resource: Resource,
  fallbackUrl?: string,
): string | undefined {
  const blobValue = resource.get(BLOB);
  const mimetypeValue = resource.get(server.properties.mimetype);

  return useBlobObjectUrl(
    typeof blobValue === 'string' ? blobValue : undefined,
    fallbackUrl,
    typeof mimetypeValue === 'string' ? mimetypeValue : undefined,
  );
}

/**
 * {@link useFileObjectUrl} for a bare blob reference (`atomic:blob:<hash>`),
 * for places that have no File resource at hand, such as an image in a
 * document, which keeps only its URL. Pass the file's `mimetype` when it is
 * known: an SVG only renders from an object URL typed `image/svg+xml`.
 */
export function useBlobObjectUrl(
  blobDid: string | undefined,
  fallbackUrl?: string,
  mimetype?: string,
): string | undefined {
  const store = useStore();
  const clientDb = store.getClientDb?.();
  // The same bytes with a different type are a different object URL.
  const cacheKey = blobDid ? `${blobDid}|${mimetype ?? ''}` : undefined;
  const [resolved, setResolved] = useState<{
    blobDid: string;
    clientDb: typeof clientDb;
    url?: string;
  }>();

  useEffect(() => {
    if (!blobDid || !isBlobSubject(blobDid) || !clientDb) return;

    if (cachedUrl(clientDb, cacheKey!)) return;

    let cancelled = false;

    (async () => {
      try {
        const hashHex = blobHashHex(blobDid);
        if (!hashHex) return;
        const hash = hexToBytes(hashHex);
        const bytes = await clientDb.getBlob(hash);
        if (cancelled) return;

        // The Blob's type becomes the object URL's Content-Type. Without it
        // an `<img>` can still sniff raster formats, but never SVG: browsers
        // only render SVG when the type is exactly `image/svg+xml`.
        const url = bytes
          ? URL.createObjectURL(
              new Blob([bytes as BlobPart], mimetype ? { type: mimetype } : {}),
            )
          : undefined;

        if (url) rememberUrl(clientDb, cacheKey!, url);

        setResolved({ blobDid, clientDb, url });
      } catch {
        if (!cancelled) setResolved({ blobDid, clientDb });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [blobDid, cacheKey, clientDb, mimetype]);

  if (!blobDid || !isBlobSubject(blobDid) || !clientDb) return fallbackUrl;

  const known = cachedUrl(clientDb, cacheKey!);

  if (known) return known;

  // A result for the previous resource/database must never leak into this render.
  if (resolved?.blobDid !== blobDid || resolved.clientDb !== clientDb) {
    return undefined;
  }

  return resolved.url ?? fallbackUrl;
}
