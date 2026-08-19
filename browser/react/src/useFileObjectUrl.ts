import { hexToBytes, server, type Resource } from '@tomic/lib';
import { useEffect, useState } from 'react';
import { useStore } from './hooks.js';

const BLOB = 'https://atomicdata.dev/properties/blob';
const BLOB_DID_PREFIX = 'did:ad:blob:';

/**
 * Returns a `blob:` object URL for the file's bytes when they are available
 * locally in the WASM clientDb (e.g. just-uploaded files, or anything cached
 * from a prior session). Returns `undefined` otherwise — callers should fall
 * back to the network `downloadURL`.
 *
 * Lets the UI preview a freshly-uploaded image even before the bytes have
 * been pushed to the server, and lets it keep working while offline.
 */
export function useFileObjectUrl(resource: Resource): string | undefined {
  const store = useStore();
  const [url, setUrl] = useState<string | undefined>(undefined);

  const blobValue = resource.get(BLOB);
  const blobDid = typeof blobValue === 'string' ? blobValue : undefined;

  const mimetypeValue = resource.get(server.properties.mimetype);
  const mimetype =
    typeof mimetypeValue === 'string' ? mimetypeValue : undefined;

  useEffect(() => {
    if (!blobDid?.startsWith(BLOB_DID_PREFIX)) {
      setUrl(undefined);

      return;
    }

    const clientDb = store.getClientDb?.();

    if (!clientDb) {
      setUrl(undefined);

      return;
    }

    let revoked: string | undefined;
    let cancelled = false;

    (async () => {
      try {
        const hash = hexToBytes(blobDid.slice(BLOB_DID_PREFIX.length));
        const bytes = await clientDb.getBlob(hash);
        if (cancelled || !bytes) return;
        // The Blob's type becomes the object URL's Content-Type. Without it
        // an `<img>` can still sniff raster formats, but never SVG — browsers
        // only render SVG when the type is exactly `image/svg+xml`.
        const u = URL.createObjectURL(
          new Blob([bytes as BlobPart], mimetype ? { type: mimetype } : {}),
        );
        revoked = u;
        setUrl(u);
      } catch {
        // ignore: caller falls back to the network downloadURL
      }
    })();

    return () => {
      cancelled = true;
      if (revoked) URL.revokeObjectURL(revoked);
    };
  }, [blobDid, mimetype, store]);

  return url;
}
