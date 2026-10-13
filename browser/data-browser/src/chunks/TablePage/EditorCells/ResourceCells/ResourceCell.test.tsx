// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { InlineFormattedResourceList } from '../../../../components/InlineFormattedResourceList';
import { ResourceCell } from './ResourceCell';

// The real cells pull in the whole view layer, whose import cycle does not load
// in isolation. They are never reached with a value that is not a subject.
vi.mock('./AgentCell', () => ({ AgentCell: () => null }));
vi.mock('./FileCell', () => ({ FileCell: () => null }));
vi.mock('./SimpleResourceLink', () => ({ SimpleResourceLink: () => null }));
vi.mock('../../../../views/ResourceInline', () => ({
  ResourceInline: () => null,
}));

afterEach(cleanup);

// No store is provided on purpose: reaching `useResource` with a value that is
// not a subject is exactly what crashed the table (`startsWith is not a
// function`), so these renders must stop before it.
describe('ResourceCell with a value that is not a subject', () => {
  it('writes an object out as text instead of looking it up', () => {
    const { container } = render(
      <ResourceCell
        subject={
          {
            'https://atomicdata.dev/task/v1/status': 'todo',
          } as unknown as string
        }
      />,
    );

    expect(container.textContent).toBe(
      '{"https://atomicdata.dev/task/v1/status":"todo"}',
    );
  });

  it('writes a number out as text', () => {
    const { container } = render(
      <ResourceCell subject={42 as unknown as string} />,
    );

    expect(container.textContent).toBe('42');
  });
});

describe('InlineFormattedResourceList with non-string entries', () => {
  it('leaves them out instead of throwing', () => {
    const { container } = render(
      <InlineFormattedResourceList
        subjects={
          [
            'https://example.com/a',
            { x: 1 },
            3,
            undefined,
          ] as unknown as string[]
        }
        RenderComp={({ subject }) => <b>{subject}</b>}
      />,
    );

    expect(container.textContent).toBe('https://example.com/a');
  });
});
