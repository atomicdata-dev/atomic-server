/** Experimental task vocabulary v1. Embedded in AtomicServer defaults. */
const base = 'https://atomicdata.dev/task/v1/';

export const taskSchema = {
  properties: {
    status: `${base}status`,
    body: `${base}body`,
    assignee: `${base}assignee`,
    dueDate: `${base}due-date`,
  },
  tags: {
    Todo: `${base}todo`,
    Doing: `${base}doing`,
    Blocked: `${base}blocked`,
    Done: `${base}done`,
  },
} as const;
