// @wc-ignore-file
import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { FancyTable } from './TableEditor';

vi.mock('./DndWrapper', () => ({
  DndWrapper: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock('./TableHeader', () => ({ TableHeader: () => <div role='row' /> }));

// Only the theme fields used by this grid fixture.
const theme = {
  colors: { main: '#4C6FA5' },
  animation: { duration: '0s' },
  size: () => '8px',
} as unknown as DefaultTheme;

function renderGrid(busy: boolean, itemCount = 1) {
  return renderToStaticMarkup(
    <ThemeProvider theme={theme}>
      <FancyTable
        busy={busy}
        columns={[]}
        itemCount={itemCount}
        columnToKey={String}
        labelledBy='table-title'
        HeadingComponent={() => <></>}
        NewColumnButtonComponent={() => null}
      >
        {() => <div role='row' />}
      </FancyTable>
    </ThemeProvider>,
  );
}

describe('table loading feedback', () => {
  it('shows a visible loading status while only the entry row is available', () => {
    const html = renderGrid(true);
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain('role="status"');
    expect(html).toContain('Loading');
    expect(html).toContain('<svg');
  });

  it.each([0, 1, 5])(
    'removes loading feedback once %i rows have settled',
    count => {
      const html = renderGrid(false, count);
      expect(html).toContain('aria-busy="false"');
      expect(html).not.toContain('role="status"');
      expect(html).not.toContain('Loading');
    },
  );
});
