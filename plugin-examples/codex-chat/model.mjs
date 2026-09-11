export const core = 'https://atomicdata.dev/properties/';
export const fields = {
  config: 'json',
  thread: 'string',
  prompt: 'string',
  state: 'string',
  transcript: 'json',
  error: 'string',
  created: 'timestamp',
  cancel: 'boolean',
  request: 'json',
  answer: 'string',
  heartbeat: 'timestamp',
};
export const terminal = new Set([
  'completed',
  'failed',
  'interrupted',
  'uncertain',
]);
export function reduceEvent(items, method, p) {
  if (method === 'item/started' || method === 'item/completed') {
    const item = p.item;
    if (!item?.id) return items;
    const index = items.findIndex(x => x.id === item.id);
    if (index < 0) return [...items, item];
    return items.map((x, i) => (i === index ? { ...x, ...item } : x));
  }
  const deltaField = {
    'item/agentMessage/delta': 'text',
    'item/commandExecution/outputDelta': 'aggregatedOutput',
  }[method];
  if (!deltaField || typeof p.delta !== 'string') return items;
  const found = items.some(x => x.id === p.itemId);
  return (
    found
      ? items
      : [
          ...items,
          {
            id: p.itemId,
            type: deltaField === 'text' ? 'agentMessage' : 'commandExecution',
          },
        ]
  ).map(x =>
    x.id === p.itemId
      ? { ...x, [deltaField]: (x[deltaField] || '') + p.delta }
      : x,
  );
}
export function approvalChoices(method, params) {
  if (
    ![
      'item/commandExecution/requestApproval',
      'item/fileChange/requestApproval',
    ].includes(method)
  )
    return [];
  const offered = params.availableDecisions;
  return ['accept', 'decline'].filter(x => !offered || offered.includes(x));
}
