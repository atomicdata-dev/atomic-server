import type { ChildProcess, SpawnOptions } from 'node:child_process';

export class OwnedProcess {
  readonly child: ChildProcess;
  readonly done: Promise<number>;
  exited: boolean;
  output: string;
  constructor(
    command: string,
    args: string[],
    options?: SpawnOptions,
    outputFd?: number,
  );
  stop(): Promise<void>;
  readyURL(timeout?: number): Promise<string>;
}
