/** GitHub-specific mapping; the host owns credentials, effects and persistence. */
import {
  reconcileRecord,
  type SyncRecord,
} from '../../browser/lib/src/plugin-reconcile.js';
import type {
  ConnectionState,
  ExternalIntent,
  ExternalReceipt,
} from '../../browser/lib/src/plugin-connection.js';

export type Status = 'Todo' | 'Doing' | 'Done';
export type Projection = {
  title: string;
  body: string;
  status: Status;
};
export interface Card {
  subject: string;
  number?: number;
  value: Projection;
}
export interface Issue {
  number: number;
  title: string;
  body: string | null;
  state: 'open' | 'closed';
  labels: Array<string | { name: string }>;
  pull_request?: unknown;
}
export interface Host {
  read(intent: ExternalIntent): Promise<ExternalReceipt>;
  cards(): Promise<Card[]>;
  state(): Promise<ConnectionState>;
}

export interface Change {
  subject?: string;
  number?: number;
  local?: Projection;
  remote?: Projection;
  desired: Projection;
}
export interface Preview {
  repository: string;
  revision: number;
  changes: Change[];
  conflicts: Array<{ subject?: string; number?: number; fields: string[] }>;
}

const headers = {
  Accept: 'application/vnd.github+json',
  'User-Agent': 'Atomic-GitHub-Issues-Pilot',
  'X-GitHub-Api-Version': '2022-11-28',
  Authorization: 'secret:github',
  'Content-Type': 'application/json',
};
export function project(issue: Issue): Projection {
  if (
    !Number.isSafeInteger(issue.number) ||
    issue.number <= 0 ||
    typeof issue.title !== 'string' ||
    !(issue.body === null || typeof issue.body === 'string') ||
    !['open', 'closed'].includes(issue.state) ||
    !Array.isArray(issue.labels)
  )
    throw new Error('GitHub returned an invalid issue');
  return {
    title: issue.title,
    body: issue.body ?? '',
    status:
      issue.state === 'closed'
        ? 'Done'
        : issue.labels.some(
              l =>
                (typeof l === 'string' ? l : l.name).toLowerCase() ===
                'atomic:doing',
            )
          ? 'Doing'
          : 'Todo',
  };
}
function validate(value: Projection) {
  if (
    typeof value.title !== 'string' ||
    !value.title.trim() ||
    typeof value.body !== 'string' ||
    !['Todo', 'Doing', 'Done'].includes(value.status)
  )
    throw new Error(
      'Cards require a title, Markdown body and exactly one Todo/Doing/Done status',
    );
}
export function endpoint(repository: string): string {
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ||
    repository.split('/').some(p => p === '.' || p === '..')
  )
    throw new Error('Repository must be owner/name');
  return `https://api.github.com/repos/${repository}/issues`;
}
export function manifest(repository: string) {
  const url = endpoint(repository);
  return {
    schemaVersion: 1,
    actions: [
      {
        name: 'get_issue',
        title: 'Get an issue',
        description: 'Read one issue from this connected repository.',
        operation: 'get',
        inputSchema: {
          type: 'object',
          properties: {
            number: { type: 'integer', description: 'Positive issue number' },
          },
          required: ['number'],
          additionalProperties: false,
        },
      },
      {
        name: 'create_issue',
        title: 'Create an issue',
        description:
          'Prepare a new issue in this repository for review. Nothing is posted until approved.',
        operation: 'create',
        inputSchema: {
          type: 'object',
          properties: {
            title: { type: 'string', description: 'Issue title' },
            body: { type: 'string', description: 'Markdown description' },
          },
          required: ['title'],
          additionalProperties: false,
        },
      },
    ],
    secrets: [
      {
        name: 'github',
        origin: 'https://api.github.com',
        description:
          'GitHub token with Issues read/write access to this repository',
      },
    ],
    operations: [
      { id: 'list', method: 'GET', url, effect: 'read' },
      { id: 'get', method: 'GET', url: `${url}/{number}`, effect: 'read' },
      { id: 'create', method: 'POST', url, effect: 'write' },
      {
        id: 'update',
        method: 'PATCH',
        url: `${url}/{number}`,
        effect: 'write',
      },
      {
        id: 'doing-add',
        method: 'POST',
        url: `${url}/{number}/labels`,
        effect: 'write',
      },
      {
        id: 'doing-remove',
        method: 'DELETE',
        url: `${url}/{number}/labels/atomic%3Adoing`,
        effect: 'write',
      },
    ],
  };
}
function parse<T>(response: ExternalReceipt): T {
  if (response.status < 200 || response.status >= 300)
    throw new Error(
      `GitHub returned ${response.status}; no checkpoint was advanced. Resolve access/rate limits before retrying.`,
    );
  return JSON.parse(response.body) as T;
}
export function request(
  operation: string,
  method: string,
  url: string,
  id: string,
  body?: unknown,
): ExternalIntent {
  return {
    operation,
    method,
    url,
    id,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}
export async function get(
  host: Host,
  root: string,
  number: number,
): Promise<Issue> {
  const issue = parse<Issue>(
    await host.read(request('get', 'GET', `${root}/${number}`, 'read')),
  );
  if ('pull_request' in issue || issue.number !== number)
    throw new Error('Expected an issue, not a pull request or another record');
  project(issue);
  return issue;
}

/** Full scans avoid interpreting a partial page as deletion. A pilot cap fails loudly. */
export async function preview(
  host: Host,
  repository: string,
): Promise<Preview> {
  const root = endpoint(repository);
  const state = await host.state();
  if (state.cursor)
    throw new Error(
      'A saved sync is pending; resume it before previewing another run',
    );
  const issues = new Map<number, Issue>();
  for (let page = 1; ; page++) {
    if (page > 100)
      throw new Error('Pilot supports at most 10,000 issues/PRs per scan');
    const rows = parse<Issue[]>(
      await host.read(
        request(
          'list',
          'GET',
          `${root}?state=all&per_page=100&page=${page}&sort=created&direction=asc`,
          `page-${page}`,
        ),
      ),
    );
    if (!Array.isArray(rows))
      throw new Error('GitHub issue page must be an array');
    for (const issue of rows)
      if (!('pull_request' in issue)) {
        project(issue);
        issues.set(issue.number, issue);
      }
    if (rows.length < 100) break;
  }
  const cards = await host.cards();
  const byNumber = new Map<number, Card>();
  for (const card of cards) {
    validate(card.value);
    if (card.number !== undefined) {
      if (byNumber.has(card.number))
        throw new Error(`Duplicate cards for issue #${card.number}`);
      byNumber.set(card.number, card);
    }
  }
  const result: Preview = {
    repository,
    revision: state.revision,
    changes: [],
    conflicts: [],
  };
  for (const [number, issue] of issues) {
    const remote = project(issue);
    const binding = state.records[String(number)];
    const card = byNumber.get(number);
    if (binding && (!card || binding.local !== card.subject)) {
      result.conflicts.push({
        number,
        fields: ['Missing or rebound local card'],
      });
      continue;
    }
    const decision = reconcileRecord(
      binding?.baseline as SyncRecord,
      card?.value,
      remote,
    );
    if (decision.conflicts.length) {
      result.conflicts.push({
        subject: card?.subject,
        number,
        fields: decision.conflicts.map(c => c.property),
      });
      continue;
    }
    const desired = { ...remote, ...decision.remote } as Projection;
    validate(desired);
    // Include unchanged records so their identity/baseline is established on first import.
    result.changes.push({
      subject: card?.subject,
      number,
      local: card?.value,
      remote,
      desired,
    });
  }
  for (const card of cards) {
    if (card.number === undefined)
      result.changes.push({
        subject: card.subject,
        local: card.value,
        desired: card.value,
      });
    else if (!issues.has(card.number))
      result.conflicts.push({
        subject: card.subject,
        number: card.number,
        fields: ['Issue missing or inaccessible; no deletion inferred'],
      });
  }
  return result;
}
