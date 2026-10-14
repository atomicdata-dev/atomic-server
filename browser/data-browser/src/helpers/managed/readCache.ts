/** Share brief bursts of account metadata reads. Nothing is persisted. */
export class ManagedReadCache {
  private entries = new Map<
    string,
    {
      response: Promise<Response>;
      expires: number;
    }
  >();

  /** Explicit refreshes (`cache` set) asked for at the same moment. */
  private pendingRefreshes = new Map<string, Promise<Response>>();

  invalidate(): void {
    this.entries.clear();
    this.pendingRefreshes.clear();
  }

  async fetch(url: string, init: RequestInit): Promise<Response> {
    const method = (init.method ?? 'GET').toUpperCase();

    if (method !== 'GET' && method !== 'HEAD') {
      // Background vault transfers, catalog reports and device heartbeats do
      // not change identity, recovery wrappers or Cloud Server enrollments.
      // Invalidating on them turns every backup into another metadata burst.
      if (/\/api\/(cloud-vault|drives\/catalog|devices|ai)(?:\/|$)/.test(url)) {
        return fetch(url, init);
      }

      // Reads that race a mutation must not populate the next read's cache.
      this.invalidate();

      try {
        return await fetch(url, init);
      } finally {
        this.invalidate();
      }
    }

    const metadata = /\/api\/(me|sync-enrollments|recovery-secret)$/.test(url);

    // An explicit refresh never reads what an earlier call left behind, but two
    // of them asked for in the same moment (two menus mounting together) are
    // one question: they share the request in flight, and nothing is kept.
    if (method === 'GET' && !init.signal && init.cache && metadata) {
      const key = JSON.stringify([
        url,
        init.credentials,
        init.cache,
        [...new Headers(init.headers).entries()].sort(),
      ]);
      const pending = this.pendingRefreshes.get(key);

      if (pending) return (await pending).clone();

      const request = fetch(url, init);
      this.pendingRefreshes.set(key, request);

      try {
        return (await request).clone();
      } finally {
        if (this.pendingRefreshes.get(key) === request) {
          this.pendingRefreshes.delete(key);
        }
      }
    }

    // Signals belong to individual callers. Requests with special fetch
    // semantics bypass sharing rather than changing another caller's read.
    if (method !== 'GET' || init.signal || init.cache || !metadata) {
      return fetch(url, init);
    }

    for (const [key, entry] of this.entries) {
      if (entry.expires <= Date.now()) this.entries.delete(key);
    }

    const key = JSON.stringify([
      url,
      init.credentials,
      [...new Headers(init.headers).entries()].sort(),
    ]);
    const existing = this.entries.get(key);

    if (existing && existing.expires > Date.now()) {
      return (await existing.response).clone();
    }

    const entry = { response: fetch(url, init), expires: Date.now() + 5000 };
    this.entries.set(key, entry);

    try {
      const response = await entry.response;

      // Anonymous, missing and failed reads must be retryable immediately.
      if (response.status !== 200 && this.entries.get(key) === entry) {
        this.entries.delete(key);
      }

      return response.clone();
    } catch (error) {
      if (this.entries.get(key) === entry) this.entries.delete(key);
      throw error;
    }
  }
}
