import React from 'react';
import styled from 'styled-components';
import { transition } from '../../helpers/transition';

interface RadioInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  disabled?: boolean;
}

export function RadioInput({
  children,
  disabled,
  ...props
}: React.PropsWithChildren<RadioInputProps>): JSX.Element {
  return (
    <Label aria-disabled={disabled}>
      <Input type='radio' {...props} disabled={disabled} />
      {children}
    </Label>
  );
}

const Label = styled.label`
  display: grid;
  grid-template-columns: 1em auto;
  gap: 0.5rem;
  line-height: 1;

  &:not([aria-disabled='true']) {
    cursor: pointer;
  }

  &[aria-disabled='true'] {
    color: ${p => p.theme.colors.textLight};
  }

  &:focus-within {
    color: ${p => p.theme.colors.main};
  }

  transition: ${transition('color')};
`;

const Input = styled.input`
  display: grid;
  transform: translateY(-0.15em);
  place-items: center;
  appearance: none;
  margin: 0;
  width: 1.15em;
  background-color: ${p => p.theme.colors.bg};
  border: solid 1px ${p => p.theme.colors.bg2};
  border-radius: 50%;
  aspect-ratio: 1/1;
  transition: ${transition('border-color')};

  &:not(:disabled):checked,
  &:not(:disabled):hover {
    border-color: ${p => p.theme.colors.main};
  }

  &::before {
    content: '';
    background-color: ${p => p.theme.colors.main};
    width: 75%;
    aspect-ratio: 1/1;
    border-radius: 50%;
    transform: scale(0);
    transition: ${transition('transform')};
  }

  &:disabled::before {
    background-color: ${p => p.theme.colors.bg2};
  }

  &:checked::before {
    transform: scale(1);
  }

  &:not(:disabled) {
    cursor: pointer;
  }

  &:focus {
    outline-color: ${p => p.theme.colors.main};
  }
`;

export const RadioGroup = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
`;
