interface OnboardingStore {
  waitForClientDb(timeoutMs: number): Promise<boolean>;
  getClientDb():
    | { waitForInit(): Promise<boolean>; initError?: Error | null }
    | undefined;
}

/** Check the actual storage engine, including worker OPFS access, before signup. */
export async function checkOnboardingStorage(
  store: OnboardingStore,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    await Promise.race([
      (async () => {
        await store.waitForClientDb(20_000);
        const db = store.getClientDb();

        if (!db || !(await db.waitForInit())) {
          throw (
            db?.initError ??
            new Error('Local storage could not be initialized.')
          );
        }
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new Error('Local storage is taking too long to initialize.'),
            ),
          20_000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
