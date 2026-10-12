// @vitest-environment jsdom
// @wc-ignore-file
import React, { useState } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render } from '@testing-library/react';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import {
  UNLIMITED,
  UsageLimitField,
  parseMaxUsages,
  type UsageLimitState,
} from './UsageLimit';

afterEach(cleanup);

const theme = { colors: {} } as unknown as DefaultTheme;

describe('parseMaxUsages', () => {
  it('is unlimited while the toggle is off, whatever is typed', () => {
    expect(parseMaxUsages({ enabled: false, value: 'junk' })).toBeUndefined();
    expect(parseMaxUsages(UNLIMITED)).toBeUndefined();
  });

  it('returns the typed whole number', () => {
    expect(parseMaxUsages({ enabled: true, value: '3' })).toBe(3);
  });

  it.each(['', ' ', '0', '-2', '1.5', 'abc'])('rejects %j', value => {
    expect(() => parseMaxUsages({ enabled: true, value })).toThrow(
      'whole number',
    );
  });
});

describe('UsageLimitField', () => {
  const Harness = ({ onState }: { onState: (s: UsageLimitState) => void }) => {
    const [limit, setLimit] = useState(UNLIMITED);

    return (
      <ThemeProvider theme={theme}>
        <UsageLimitField
          limit={limit}
          onChange={next => {
            setLimit(next);
            onState(next);
          }}
        />
      </ThemeProvider>
    );
  };

  it('starts unlimited, without a number field', () => {
    const { getByLabelText, queryByLabelText } = render(
      <Harness onState={() => undefined} />,
    );

    expect((getByLabelText('Limit uses') as HTMLInputElement).checked).toBe(
      false,
    );
    expect(queryByLabelText('Maximum number of people')).toBeNull();
  });

  it('shows the number field once on, and reports what is typed', () => {
    let state = UNLIMITED;
    const { getByLabelText } = render(<Harness onState={s => (state = s)} />);

    fireEvent.click(getByLabelText('Limit uses'));
    expect(state).toEqual({ enabled: true, value: '1' });

    fireEvent.change(getByLabelText('Maximum number of people'), {
      target: { value: '5' },
    });
    expect(parseMaxUsages(state)).toBe(5);
  });
});
