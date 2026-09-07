import { test, expect } from './fixtures';
import {
  before,
  editableTitle,
  waitForClientDbFlush,
  waitForDriveSettled,
  waitForSynced,
} from './test-utils';

/**
 * Regression test: after creating a fresh dev-drive and refreshing the
 * page, no `/query?...` request — over WS or HTTP — should carry a
 * `drive=<server-origin>` filter. The old fallback in CollectionBuilder
 * defaulted `drive` to the server URL string (e.g. `http://localhost:9883`)
 * when the caller didn't `setDrive(...)`. The server then filters
 * `drive == "http://localhost:9883"`, which never matches any real
 * resource (resources are scoped by drive DID), so every default-drive
 * query returned zero rows — wasted work that the user noticed in their
 * console: tons of `/query?drive=http%3A%2F%2Flocalhost%3A9883&...`
 * requests on `/app/sync` after a hard refresh.
 *
 * Note: most `/query` traffic flows over the WebSocket (the store
 * prefers `ws.fetch(subject)` when the socket is open, see
 * `store.ts:1441`), so the regression has to listen for WS frames in
 * addition to HTTP GETs.
 */
test.describe('query GETs after refresh', () => {
  test.beforeEach(before);

  test('no /query request uses the server origin as a drive filter', async ({
    page,
  }) => {
    const badRequests: string[] = [];

    const isBad = (url: string) => {
      if (!url.includes('/query?')) return false;

      try {
        const u = new URL(url, 'http://placeholder');
        const drive = u.searchParams.get('drive');
        if (!drive) return false;

        // Valid: did:ad:... DID. Invalid: any HTTP(S) URL string.
        return !drive.startsWith('did:ad:');
      } catch {
        return false;
      }
    };

    page.on('request', req => {
      if (req.method() !== 'GET') return;
      if (isBad(req.url())) badRequests.push('HTTP ' + req.url());
    });

    page.on('websocket', ws => {
      ws.on('framesent', frame => {
        // WS v2 frames are text — `GET <url>` for a fetch. The full URL
        // appears verbatim; scan each whitespace-separated token.
        const payload = frame.payload?.toString() ?? '';

        for (const word of payload.split(/\s+/)) {
          if (isBad(word)) badRequests.push('WS ' + word);
        }
      });
    });

    // Hard refresh — this is the bootstrap path where useCollection /
    // useChildren hooks build their CollectionBuilders.
    await page.reload({ waitUntil: 'domcontentloaded' });

    await waitForDriveSettled(page);

    expect(
      badRequests,
      'Found /query requests with non-DID drive filter. Drive filter must ' +
        'be a did:ad:... DID, never a server-origin URL:\n' +
        badRequests.map(u => '  ' + u).join('\n'),
    ).toEqual([]);
  });

  /**
   * Regression test: after a hard refresh on a drive whose contents are
   * already in OPFS, the collection layer must serve queries from the
   * local WASM DB. No `/query?…` WS frames and no per-subject GETs for
   * already-cached resources should fire.
   *
   * Background (user-observed): refreshing a populated drive produced
   * 30+ WS GET frames — duplicate `/query?parent=drive` plus per-
   * subject GETs for every child the drive already had cached. The
   * `Collection.fetchPage` race kicks a `fetchPageFromServer` in
   * parallel with the local-DB lookup; when local wins, the server
   * response is pure wasted bandwidth.
   *
   * Contract: on a fresh dev-drive with at least one child resource,
   * after a hard refresh, count the `→ GET` WS frames issued AFTER the
   * initial drive `SUB` resolves. The expected post-fix count is 0.
   * Per-subject WS GETs are encoded as a single subject string per
   * frame (e.g. `did:ad:…`). `/query?` GETs are full URLs.
   */
  test('refresh on a populated drive does not refetch known resources from server', async ({
    page,
  }) => {
    // Seed the drive with one document so children-of-drive isn't empty.
    await page
      .getByTestId('sidebar')
      .getByRole('button', { name: 'New Document' })
      .click();
    await expect(editableTitle(page)).toBeVisible({ timeout: 10000 });

    // Wait until everything is committed and synced — including the
    // OPFS persist of the new document. If we reload before OPFS has
    // the data, the post-reload server queries are legitimate (cold
    // load), not the bug we're testing.
    await waitForSynced(page);
    await waitForClientDbFlush(page);

    // Wire WS listeners BEFORE reload so we don't miss any framesent.
    // WS v2 framing is BINARY — see `ws-v2.ts:Tag`. GET = 0x10, encoded
    // as [0x10][u16 requestId][subject_bytes]. Playwright's framesent
    // gives us the raw payload as Buffer (Node) or string of bytes
    // (browser). We sniff the first byte for the GET tag.
    const WS_TAG_GET = 0x10;
    const wsGetFrames: string[] = [];
    page.on('websocket', ws => {
      ws.on('framesent', frame => {
        const raw = frame.payload;
        if (!raw) return;
        // Buffer in Node, ArrayBuffer / string in browser context.
        let firstByte: number | undefined;
        let asString: string;

        if (typeof raw === 'string') {
          firstByte = raw.charCodeAt(0);
          asString = raw;
        } else {
          // Buffer or Uint8Array
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const b = raw as any;
          firstByte = b[0];
          asString = b.toString('utf8');
        }

        if (firstByte === WS_TAG_GET) {
          // Skip tag + 2-byte requestId; subject is the rest as UTF-8.
          wsGetFrames.push(asString.slice(3, 253));
        }
      });
    });

    await page.reload({ waitUntil: 'domcontentloaded' });

    // Wait for steady state: WS connected, ClientDb ready, and the
    // OPFS bootstrap-fingerprint check has completed (logged as
    // "skipping seed" when the fingerprint matches).
    await waitForDriveSettled(page);

    // Drop frames from the bootstrap window. `Collection.fetchPage` falls
    // through to `/query` while ClientDb isn't ready (or before this drive
    // has completed a local sync) — those are cold-load fetches, not the
    // redundant post-ready storm this regression guards. Clear once the
    // drive has settled, then watch only the window where the local WASM
    // DB must win — the sidebar showing the seeded document is that UI.
    wsGetFrames.length = 0;
    await expect(editableTitle(page)).toBeVisible({ timeout: 15000 });

    // No `/query?` frames should fire at all — those are exclusively
    // collection queries that the local WASM DB can serve.
    const queryFrames = wsGetFrames.filter(f => f.includes('/query?'));
    expect(
      queryFrames,
      'After ClientDb is ready, no `/query?` WS GET should fire (collection ' +
        'layer must serve from local WASM DB).\n' +
        queryFrames.map(u => '  ' + u).join('\n'),
    ).toEqual([]);

    // Per-subject GETs may fire for resources that aren't in OPFS yet
    // when the first `useResource(...)` mounts (the bootstrap order is
    // racy — see store.ts:fetchResourceWithLocalFallback). The
    // regression we care about is the storm: pre-fix the user saw
    // 20–30+ frames; post-fix we want a handful.
    //
    // Threshold 10 (not 0): under suite-wide load (Playwright `workers=2+`),
    // the WS connects + auths slower, more `useResource()` calls hit before
    // ClientDb is `isReady`, and the DriveSwitcher's `useSavedDrives` flow
    // can pull in extra agent.drives entries. Solo runs settle at ≤2; the
    // 5× headroom covers parallel contention without masking a real
    // regression — anything in the 20+ range will still fail.
    const subjectFrames = wsGetFrames.filter(f => !f.includes('/query?'));
    expect(
      subjectFrames.length,
      'After ClientDb is ready, the per-subject WS GET count should be tiny — ' +
        'pre-fix this routinely hit 20+ on a populated drive. Found ' +
        subjectFrames.length +
        ':\n' +
        subjectFrames.map(u => '  ' + u).join('\n'),
    ).toBeLessThanOrEqual(10);
  });
});
