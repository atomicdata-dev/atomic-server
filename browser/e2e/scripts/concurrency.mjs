import {
  availableParallelism,
  freemem,
  totalmem,
  platform,
  release,
} from 'node:os';

export function positiveInteger(value, name) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1)
    throw new Error(`${name} must be a positive integer, received ${value}`);

  return number;
}

export function workerBudget(
  env = process.env,
  hardware = {
    cpus: availableParallelism(),
    freeBytes: freemem(),
    totalBytes: totalmem(),
  },
) {
  // Leave CPU and memory for the server, template builds and other jobs.
  // Conservative ceiling until the zero-retry acceptance matrix establishes more.
  const automatic = Math.max(
    1,
    Math.min(
      env.CI ? 1 : 2,
      Math.floor(hardware.cpus / 2),
      Math.floor(hardware.freeBytes / (2 * 1024 ** 3)),
    ),
  );

  return {
    ...hardware,
    platform: platform(),
    release: release(),
    workers:
      env.PLAYWRIGHT_WORKERS === undefined
        ? automatic
        : positiveInteger(env.PLAYWRIGHT_WORKERS, 'PLAYWRIGHT_WORKERS'),
    override: env.PLAYWRIGHT_WORKERS !== undefined,
  };
}
