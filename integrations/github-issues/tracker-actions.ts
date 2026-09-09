/** Additional repository-scoped actions used by the Devonian tracker bridge. */
import { endpoint, request } from './adapter.js';

const integer = {
  type: 'integer' as const,
  description: 'Positive identifier or page number',
};
const string = {
  type: 'string' as const,
  description: 'Issue or comment field value',
};
const definitions = [
  ['list_issues', 'List issues', 'list', { page: integer }, ['page']],
  [
    'update_issue',
    'Update an issue',
    'update',
    { number: integer, title: string, body: string, state: string },
    ['number', 'title', 'body', 'state'],
  ],
  [
    'add_doing_label',
    'Mark an issue as doing',
    'doing-add',
    { number: integer },
    ['number'],
  ],
  [
    'remove_doing_label',
    'Remove the doing label',
    'doing-remove',
    { number: integer },
    ['number'],
  ],
  [
    'list_comments',
    'List issue comments',
    'comments-list',
    { number: integer, page: integer },
    ['number', 'page'],
  ],
  [
    'get_comment',
    'Get an issue comment',
    'comments-get',
    { id: integer },
    ['id'],
  ],
  [
    'create_comment',
    'Create an issue comment',
    'comments-create',
    { number: integer, body: string },
    ['number', 'body'],
  ],
  [
    'update_comment',
    'Update an issue comment',
    'comments-update',
    { id: integer, body: string },
    ['id', 'body'],
  ],
] as const;

export const trackerActions = definitions.map(
  ([name, title, operation, properties, required]) => ({
    name,
    title,
    description: `${title} in this connected repository. Writes require approval.`,
    operation,
    inputSchema: {
      type: 'object',
      properties,
      required: [...required],
      additionalProperties: false,
    },
  }),
);

export function trackerOperations(root: string) {
  return [
    {
      id: 'comments-list',
      method: 'GET',
      url: `${root}/{number}/comments`,
      effect: 'read',
    },
    {
      id: 'comments-get',
      method: 'GET',
      url: `${root}/comments/{id}`,
      effect: 'read',
    },
    {
      id: 'comments-create',
      method: 'POST',
      url: `${root}/{number}/comments`,
      effect: 'write',
    },
    {
      id: 'comments-update',
      method: 'PATCH',
      url: `${root}/comments/{id}`,
      effect: 'write',
    },
  ];
}

export function trackerAction(
  repository: string,
  action: string,
  args: Record<string, unknown>,
) {
  const definition = definitions.find(d => d[0] === action);
  if (!definition) return undefined;
  const [, , operation, properties, required] = definition;
  for (const key of required) {
    if (!(key in args)) throw new Error(`Missing ${key}`);
  }
  for (const [key, value] of Object.entries(args)) {
    if (!(key in properties)) throw new Error(`Unexpected ${key}`);
    if (['number', 'id', 'page'].includes(key)) {
      if (
        !Number.isSafeInteger(value) ||
        Number(value) <= 0 ||
        (key === 'page' && Number(value) > 100)
      )
        throw new Error(`Invalid ${key}`);
    } else if (typeof value !== 'string') throw new Error(`Invalid ${key}`);
  }
  const root = endpoint(repository);
  switch (action) {
    case 'list_issues':
      return request(
        operation,
        'GET',
        `${root}?state=all&per_page=100&page=${args.page}&sort=created&direction=asc`,
        'action',
      );
    case 'list_comments':
      return request(
        operation,
        'GET',
        `${root}/${args.number}/comments?per_page=100&page=${args.page}`,
        'action',
      );
    case 'get_comment':
      return request(operation, 'GET', `${root}/comments/${args.id}`, 'action');
    case 'create_comment':
    case 'update_comment':
      if (!(args.body as string).trim())
        throw new Error('Comment body cannot be empty');
      return request(
        operation,
        action === 'create_comment' ? 'POST' : 'PATCH',
        action === 'create_comment'
          ? `${root}/${args.number}/comments`
          : `${root}/comments/${args.id}`,
        'action',
        { body: args.body },
      );
    case 'add_doing_label':
      return request(
        operation,
        'POST',
        `${root}/${args.number}/labels`,
        'action',
        {
          labels: ['atomic:doing'],
        },
      );
    case 'remove_doing_label':
      return request(
        operation,
        'DELETE',
        `${root}/${args.number}/labels/atomic%3Adoing`,
        'action',
      );
    case 'update_issue':
      if (!['open', 'closed'].includes(String(args.state)))
        throw new Error('Invalid issue state');
      if (!(args.title as string).trim() || (args.title as string).length > 256)
        throw new Error('Invalid issue title');
      return request(operation, 'PATCH', `${root}/${args.number}`, 'action', {
        title: args.title,
        body: args.body,
        state: args.state,
      });
  }
}
