export type E2eBudget = {
  shardCount: number;
  workers: string;
  retries: string;
  grep: string;
};

/** Zero workers/shards and -1 retries retain the named host profile. */
export function overrideE2eBudget(
  defaults: E2eBudget,
  workers = 0,
  shards = 0,
  retries = -1,
): E2eBudget {
  for (const [name, value, minimum] of [
    ['workers', workers, 0],
    ['shards', shards, 0],
    ['retries', retries, -1],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < minimum) {
      throw new Error(`Playwright ${name} must be an integer >= ${minimum}`);
    }
  }

  return {
    ...defaults,
    workers: workers === 0 ? defaults.workers : String(workers),
    shardCount: shards === 0 ? defaults.shardCount : shards,
    retries: retries === -1 ? defaults.retries : String(retries),
  };
}
