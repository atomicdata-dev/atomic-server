/**
 * Host ABI types for frames. Hand-written mirror of
 * `atomic-host/wit/host.wit` (interfaces `types` and `calls`); the error codes
 * are checked against `server/src/plugins/host_abi/mod.rs` by `hostAbi.test.ts`.
 * WIT is the source: change it first, then this file.
 */

/** `error.code` in WIT: stable, machine-readable. */
export const HOST_ERROR_CODES = [
  'not-found',
  'forbidden',
  'invalid-argument',
  'unsupported',
  'depth-exceeded',
  'needs-approval',
  'trap',
  'internal',
] as const;

export type HostErrorCode = (typeof HOST_ERROR_CODES)[number];

/** `calls.effect`: what calling an export may do. */
export type Effect = 'read' | 'write' | 'external' | 'interactive';

/** `calls.app-export`: one function an installed app declares in its manifest. */
export interface AppExport {
  /** `atomic:tasks/manage@1`. */
  interface: string;
  function: string;
  description: string;
  /** JSON Schema of the arguments. */
  inputSchema: unknown;
  /** JSON Schema of the result. */
  outputSchema: unknown;
  effect: Effect;
}

/** A failed host call. `code` is stable; `message` is for people. */
export class HostError extends Error {
  public constructor(
    public readonly code: HostErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'HostError';
  }
}

/** A code from the host, or `internal` for one this version does not know. */
export function toHostErrorCode(code: unknown): HostErrorCode {
  return HOST_ERROR_CODES.includes(code as HostErrorCode)
    ? (code as HostErrorCode)
    : 'internal';
}
