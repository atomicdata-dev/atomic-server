// @wc-ignore-file
import { hexToBytes, signRequest, type Store } from '@tomic/lib';

export interface WebsiteAsset {
  hash: string;
  mimeType: string;
}

export async function storeWebsiteAsset(
  store: Store,
  blob: Blob,
): Promise<WebsiteAsset> {
  const db = store.getClientDb();
  if (!db) throw new Error('Image export requires local blob storage.');
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const hashBytes = await db.blake3Hash(bytes);
  await db.putBlob(hashBytes, bytes);

  return {
    hash: Array.from(hashBytes, b => b.toString(16).padStart(2, '0')).join(''),
    mimeType: blob.type,
  };
}

async function assetRequest(
  store: Store,
  project: string,
  hash: string,
  body?: Blob,
) {
  const agent = store.getAgent();
  const drive = store.getDrive();
  if (!agent || !drive) throw new Error('Sign in to access website assets.');
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error('Invalid image blob hash.');
  const url = new URL(`/website-hosting/assets/${hash}`, store.getServerUrl());
  url.searchParams.set('project', project);
  url.searchParams.set('drive', drive);
  // The signature covers these exact bytes, so read the blob once and send
  // what was signed.
  const bytes = body ? new Uint8Array(await body.arrayBuffer()) : undefined;
  const headers = await signRequest(
    url.toString(),
    agent,
    {},
    bytes ? { method: 'POST', body: bytes } : undefined,
  );
  const response = await fetch(url, {
    method: bytes ? 'POST' : 'GET',
    headers,
    credentials: 'omit',
    redirect: 'error',
    body: bytes,
  });
  if (!response.ok)
    throw new Error(
      `Website image blob request failed (${response.status}): ${await response.text()}`,
    );

  return response;
}

export async function readWebsiteAsset(
  store: Store,
  project: string,
  asset: WebsiteAsset,
): Promise<Blob> {
  const db = store.getClientDb();
  const hash = hexToBytes(asset.hash);
  let bytes = await db?.getBlob(hash);

  if (!bytes) {
    bytes = new Uint8Array(
      await (await assetRequest(store, project, asset.hash)).arrayBuffer(),
    );
    if (!db) throw new Error('Image verification requires local blob storage.');
    const actual = await db.blake3Hash(bytes);
    if (actual.some((b, i) => b !== hash[i]))
      throw new Error('Image blob integrity check failed.');
    await db.putBlob(hash, bytes);
  }

  return new Blob([bytes as BlobPart], { type: asset.mimeType });
}
export async function uploadWebsiteAssets(
  store: Store,
  project: string,
  assets: Record<string, WebsiteAsset> = {},
) {
  for (const asset of Object.values(assets)) {
    await assetRequest(
      store,
      project,
      asset.hash,
      await readWebsiteAsset(store, project, asset),
    );
  }
}
