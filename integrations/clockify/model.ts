// @wc-ignore-file
export const origin = 'https://api.clockify.me';
export const api = `${origin}/api/v1`;
export function id(value: string) {
  if (!/^[a-f\d]{24}$/i.test(value))
    throw new Error('Invalid Clockify identifier');
  return value;
}
export function manifest(workspace?: string, user?: string) {
  return {
    schemaVersion: 1,
    secrets: [
      {
        name: 'clockify',
        origin,
        description:
          'Clockify API key. Used only for reading your workspaces, projects and completed entries.',
      },
    ],
    operations: [
      { id: 'user', method: 'GET', url: `${api}/user`, effect: 'read' },
      {
        id: 'workspaces',
        method: 'GET',
        url: `${api}/workspaces`,
        effect: 'read',
      },
      ...(workspace && user
        ? [
            {
              id: 'projects',
              method: 'GET',
              url: `${api}/workspaces/${id(workspace)}/projects`,
              effect: 'read',
            },
            {
              id: 'entries',
              method: 'GET',
              url: `${api}/workspaces/${id(workspace)}/user/${id(user)}/time-entries`,
              effect: 'read',
            },
          ]
        : []),
    ],
  };
}
export function request(operation: string, url: string, run = operation) {
  return {
    operation,
    method: 'GET',
    url,
    id: run,
    headers: { 'X-Api-Key': 'secret:clockify' },
  };
}
export function parse(receipt: { status: number; body: string }): unknown {
  if (receipt.status !== 200)
    throw new Error(
      `Clockify returned ${receipt.status}. Check access and API limits, then retry.`,
    );
  return JSON.parse(receipt.body);
}
export interface Config {
  workspace: string;
  user: string;
  userName: string;
  /** Legacy fixed windows remain supported for existing installed importers. */
  start?: string;
  end?: string;
  /** Rolling window, resolved from the host-provided trigger instant. */
  lookbackDays?: number;
  drive: string;
  /** App-owned supporting resources live here; legacy configurations fall back to their table. */
  container?: string;
  table: string;
  rowClass: string;
  projectClass: string;
  personClass: string;
  properties: {
    start: string;
    end: string;
    project: string;
    person: string;
    billable: string;
    identity: string;
  };
}
