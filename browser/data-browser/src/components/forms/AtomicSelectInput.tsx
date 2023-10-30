import { Resource, useValue } from '@tomic/react';
import React from 'react';
import { InputWrapper } from './InputStyles';
import { styled, css } from 'styled-components';

interface AtomicSelectInputProps {
  resource: Resource;
  property: string;
  options: {
    value: string;
    label: string;
  }[];
  commit?: boolean;
}

type Props = AtomicSelectInputProps &
  Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'resource'>;

export function AtomicSelectInput({
  resource,
  property,
  options,
  commit = false,
  ...props
}: Props): JSX.Element {
  const [value, setValue] = useValue(resource, property, { commit });

  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setValue(e.target.value);
  };

  return (
    <InputWrapper>
      <SelectWrapper disabled={!!props.disabled}>
        <Select {...props} onChange={handleChange} value={value as string}>
          {options.map(option => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
      </SelectWrapper>
    </InputWrapper>
  );
}

const SelectWrapper = styled.span<{ disabled: boolean }>`
  width: 100%;
  padding-inline: 0.2rem;

  ${p =>
    p.disabled &&
    css`
      background-color: ${props => props.theme.colors.bg1};
    `}
`;

const Select = styled.select`
  width: 100%;
  border: none;
  outline: none;
  height: 2rem;

  &:disabled {
    color: ${props => props.theme.colors.textLight};
    background-color: transparent;
  }
`;
