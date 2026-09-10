import type { Store } from '@tomic/lib';

export interface Demo {
  key: string;
  state: {
    options: { sample: boolean };
    config: { connection: { table: string } };
    fixture: {
      issues?: Array<{ number: number; title: string; state: string }>;
      comments?: Array<{ id: number; body: string; issue_url: string }>;
    };
  };
}
export interface Row {
  id: string;
  value: { title: string; body: string; status: string };
  comments: Array<{ id: string; value: { body: string } }>;
}
export function openDemo(
  store: Store,
  options: {
    sample: boolean;
    repository: string;
    proxy: string;
  },
): Promise<Demo>;
export function syncDemo(store: Store, demo: Demo): Promise<number>;
export function demoRows(store: Store, demo: Demo): Promise<Row[]>;
export function editAtomic(
  store: Store,
  demo: Demo,
  command: string,
  id?: string,
  text?: string,
): Promise<void>;
export function editFixture(
  demo: Demo,
  command: string,
  number?: number,
  text?: string,
): Promise<void>;

export function connectDemo(
  store: Store,
  options: { repository: string; proxy: string },
  secret: string,
): Promise<void>;
export function resumeDemo(store: Store): Promise<Demo | undefined>;
