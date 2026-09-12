export function positiveInteger(value: string | number, name: string): number;
export function workerBudget(
  env?: NodeJS.ProcessEnv,
  hardware?: { cpus: number; freeBytes: number; totalBytes: number },
): {
  cpus: number;
  freeBytes: number;
  totalBytes: number;
  workers: number;
  override: boolean;
};
