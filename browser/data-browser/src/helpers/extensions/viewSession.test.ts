import { expect, it, vi } from 'vitest';
import { viewSession } from './viewSession';

it('gives both adapters the same response and resource shape', () => {
  const post = vi.fn();
  const session = viewSession(
    { post, isActive: () => true, watch: vi.fn(), unwatch: vi.fn() },
    'one',
  );
  session.post({
    id: 1,
    result: { subject: 'row', title: 'Row', propVals: { name: 'Row' } },
  });
  const generated = post.mock.calls[0][0];
  session.post({
    type: 'response',
    requestId: 'old',
    data: {
      subject: 'row',
      title: 'Row',
      props: { name: 'Row' },
      loading: false,
    },
  });
  expect(post.mock.calls[1][0]).toEqual(generated);
  expect(generated).toMatchObject({
    type: 'atomic.view.response',
    version: 1,
    id: 'one',
    result: { subject: 'row', props: { name: 'Row' } },
  });
  session.post({ type: 'error', error: 'denied', message: 'Not allowed' });
  expect(post).toHaveBeenLastCalledWith({
    type: 'atomic.view.response',
    version: 1,
    id: 'one',
    error: 'Not allowed',
  });
});
