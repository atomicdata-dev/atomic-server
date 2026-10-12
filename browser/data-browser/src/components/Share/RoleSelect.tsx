import { styled } from 'styled-components';
import { FaCaretDown } from 'react-icons/fa6';

import type { JSX } from 'react';
import { SegmentedControl } from './SegmentedControl';

export type ShareRole = 'write' | 'read';

interface RoleSelectProps {
  value: ShareRole;
  onChange: (role: ShareRole | 'remove') => void;
  /** Adds a "Remove access" option, for people who already have access */
  allowRemove?: boolean;
  disabled?: boolean;
  'aria-label': string;
  /** Renders without a background, e.g. inside a bordered split button */
  plain?: boolean;
}

/**
 * Compact "Can write ▾" picker. A native select, so keyboard and screen reader
 * behaviour come for free and it opens as the OS sheet on phones.
 */
export function RoleSelect({
  value,
  onChange,
  allowRemove,
  disabled,
  plain,
  'aria-label': ariaLabel,
}: RoleSelectProps): JSX.Element {
  return (
    <Wrapper $plain={plain}>
      <Select
        value={value}
        disabled={disabled}
        aria-label={ariaLabel}
        onChange={e => onChange(e.target.value as ShareRole | 'remove')}
      >
        <option value='write'>Can write</option>
        <option value='read'>Can read</option>
        {allowRemove && <option value='remove'>Remove access</option>}
      </Select>
      <FaCaretDown aria-hidden />
    </Wrapper>
  );
}

const ROLE_OPTIONS: { value: ShareRole; label: string }[] = [
  { value: 'read', label: 'Read' },
  { value: 'write', label: 'Write' },
];

/**
 * Read / Write as a single-click switch, styled like the Public switch. For
 * choosing what an invite grants, where there is no "off" and no "remove".
 */
export function RoleSwitch({
  value,
  onChange,
  disabled,
  'aria-label': ariaLabel,
}: {
  value: ShareRole;
  onChange: (role: ShareRole) => void;
  disabled?: boolean;
  'aria-label': string;
}): JSX.Element {
  return (
    <SegmentedControl
      options={ROLE_OPTIONS}
      value={value}
      onChange={onChange}
      disabled={disabled}
      aria-label={ariaLabel}
    />
  );
}

export function roleLabel(role: ShareRole): string {
  return role === 'write' ? 'Can write' : 'Can read';
}

const Wrapper = styled.span<{ $plain?: boolean }>`
  position: relative;
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => (p.$plain ? 'transparent' : p.theme.colors.bg1)};
  color: ${p => p.theme.colors.text};
  transition: background-color 100ms ease-in-out;

  &:hover:has(select:not(:disabled)) {
    background-color: ${p => p.theme.colors.bg2};
  }

  &:focus-within {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: 1px;
  }

  svg {
    position: absolute;
    right: 0.6rem;
    font-size: 0.7rem;
    pointer-events: none;
    color: ${p => p.theme.colors.textLight};
  }
`;

const Select = styled.select`
  appearance: none;
  border: none;
  background: transparent;
  color: inherit;
  font: inherit;
  font-size: 0.95rem;
  cursor: pointer;
  padding: 0.4rem 1.7rem 0.4rem 0.75rem;
  outline: none;

  &:disabled {
    cursor: default;
  }

  option {
    color: initial;
  }
`;
