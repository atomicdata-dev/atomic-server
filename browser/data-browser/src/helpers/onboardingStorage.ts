interface OnboardingStore {
  waitForClientDb(timeoutMs: number): Promise<boolean>;
  waitForServerConnected?(timeoutMs: number): Promise<boolean>;
  getClientDb():
    | { waitForInit(): Promise<boolean>; initError?: Error | null }
    | undefined;
}

/** Check the actual storage engine, including worker OPFS access, before signup. */
export async function checkOnboardingStorage(
  store: OnboardingStore,
  nativeNodeOrigin?: string,
  fetchNode: typeof fetch = fetch,
  clientDbEnabled = true,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    await Promise.race([
      (async () => {
        if (nativeNodeOrigin) {
          // Tauri persists in its embedded node and deliberately has no ClientDb.
          // The webview can load before that node has finished starting.
          while (true) {
            let nodeReady = false;

            try {
              const response = await fetchNode(`${nativeNodeOrigin}/server`, {
                headers: { Accept: 'application/json' },
              });
              const node = await response.json();
              nodeReady = response.ok && node?.['@id'] === 'internal:/server';
            } catch {
              // Keep trying until the shared deadline below.
            }

            if (nodeReady) {
              // HTTP can answer before the Store's authenticated WebSocket
              // connects. An offline save has no browser database in Tauri.
              if (
                !store.waitForServerConnected ||
                !(await store.waitForServerConnected(20_000))
              ) {
                throw new Error('The local node is not connected.');
              }

              return;
            }

            await new Promise(resolve => setTimeout(resolve, 250));
          }
        } else if (!clientDbEnabled) {
          // The user chose server-only mode. Gate saves on the actual socket,
          // rather than waiting for a worker that will never be started.
          if (
            !store.waitForServerConnected ||
            !(await store.waitForServerConnected(20_000))
          ) {
            throw new Error('The server is not connected.');
          }
        } else {
          await store.waitForClientDb(20_000);
          const db = store.getClientDb();

          if (!db || !(await db.waitForInit())) {
            throw (
              db?.initError ??
              new Error('Local storage could not be initialized.')
            );
          }
        }
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new Error(
                nativeNodeOrigin
                  ? 'The local node is taking too long to start.'
                  : 'Local storage is taking too long to initialize.',
              ),
            ),
          20_000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
