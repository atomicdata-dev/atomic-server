import { useId, type JSX } from 'react';
import { styled } from 'styled-components';

interface SegmentedControlProps<T extends string> {
  options: { value: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
  disabled?: boolean;
  'aria-label': string;
}

/**
 * Single-click switch between a few options, shown side by side. Radio inputs
 * underneath, so arrow keys and screen readers work as for any radio group.
 */
export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  disabled,
  'aria-label': ariaLabel,
}: SegmentedControlProps<T>): JSX.Element {
  const name = useId();

  return (
    <Segmented role='radiogroup' aria-label={ariaLabel}>
      {options.map(option => (
        <SegmentLabel key={option.value}>
          <input
            type='radio'
            name={name}
            value={option.value}
            checked={value === option.value}
            disabled={disabled}
            onChange={() => onChange(option.value)}
          />
          <span>{option.label}</span>
        </SegmentLabel>
      ))}
    </Segmented>
  );
}

const Segmented = styled.div`
  display: inline-flex;
  flex-shrink: 0;
  padding: 0.2rem;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg2};
  background-color: color-mix(
    in srgb,
    ${p => p.theme.colors.bg2} 45%,
    ${p => p.theme.colors.bg1}
  );
`;

const SegmentLabel = styled.label`
  position: relative;

  input {
    position: absolute;
    opacity: 0;
    inset: 0;
    margin: 0;
    cursor: pointer;
  }

  input:disabled {
    cursor: default;
  }

  span {
    display: block;
    padding: 0.35rem 0.8rem;
    border-radius: calc(${p => p.theme.radius} - 2px);
    color: ${p => p.theme.colors.textLight};
    font-size: 0.95rem;
    transition:
      background-color 100ms ease-in-out,
      color 100ms ease-in-out;
  }

  input:checked + span {
    background-color: ${p => p.theme.colors.bg};
    color: ${p => p.theme.colors.text};
    box-shadow: 0 1px 2px rgb(0 0 0 / 0.12);
  }

  input:focus-visible + span {
    outline: 2px solid ${p => p.theme.colors.main};
  }

  input:not(:checked):not(:disabled):hover + span {
    color: ${p => p.theme.colors.text};
  }
`;
