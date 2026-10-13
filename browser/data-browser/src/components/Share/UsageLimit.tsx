import type { JSX } from 'react';
import { styled } from 'styled-components';

export interface UsageLimitState {
  /** Whether the link stops working after a number of people used it */
  enabled: boolean;
  /** What is typed in the number field */
  value: string;
}

export const UNLIMITED: UsageLimitState = { enabled: false, value: '1' };

/**
 * The number of people the link admits, or undefined when unlimited. Throws
 * on something that cannot be a limit, so nobody gets a link that admits
 * nobody (or half a person).
 */
export function parseMaxUsages(limit: UsageLimitState): number | undefined {
  if (!limit.enabled) return undefined;

  const parsed = Number(limit.value);

  if (
    limit.value.trim() === '' ||
    !Number.isSafeInteger(parsed) ||
    parsed < 1
  ) {
    throw new Error('Enter a whole number of at least 1 as the limit.');
  }

  return parsed;
}

interface UsageLimitFieldProps {
  limit: UsageLimitState;
  onChange: (limit: UsageLimitState) => void;
  disabled?: boolean;
}

/**
 * A small, optional control next to an invite link: off means anyone with the
 * link can join, on means only the first N people can.
 */
export function UsageLimitField({
  limit,
  onChange,
  disabled,
}: UsageLimitFieldProps): JSX.Element {
  return (
    <Row>
      <Toggle>
        <input
          type='checkbox'
          checked={limit.enabled}
          disabled={disabled}
          data-test='invite-limit-toggle'
          onChange={e => onChange({ ...limit, enabled: e.target.checked })}
        />
        <span>Limit uses</span>
      </Toggle>
      {limit.enabled && (
        <>
          <NumberInput
            type='number'
            inputMode='numeric'
            min={1}
            step={1}
            value={limit.value}
            disabled={disabled}
            aria-label='Maximum number of people'
            data-test='invite-max-usages'
            onChange={e => onChange({ ...limit, value: e.target.value })}
          />
          {limit.value === '1' ? (
            <span>person can join</span>
          ) : (
            <span>people can join</span>
          )}
        </>
      )}
    </Row>
  );
}

const Row = styled.div`
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
  font-size: 0.9em;
  color: ${p => p.theme.colors.textLight};
`;

const Toggle = styled.label`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  cursor: pointer;
  user-select: none;
`;

const NumberInput = styled.input`
  width: 4.5rem;
  padding: 0.2rem 0.5rem;
  font: inherit;
  color: ${p => p.theme.colors.text};
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
`;
