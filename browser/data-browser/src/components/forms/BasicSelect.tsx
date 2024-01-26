import { styled } from 'styled-components';
import { InputWrapper } from './InputStyles';
import { FC, PropsWithChildren } from 'react';

type Props = React.SelectHTMLAttributes<HTMLSelectElement>;

export const BasicSelect: FC<PropsWithChildren<Props>> = ({
  children,
  ...props
}) => {
  return (
    <StyledInputWrapper>
      <SelectWrapper disabled={!!props.disabled}>
        <Select {...props}>{children}</Select>
      </SelectWrapper>
    </StyledInputWrapper>
  );
};

const StyledInputWrapper = styled(InputWrapper)`
  min-width: 15ch;
`;

const SelectWrapper = styled.span<{ disabled: boolean }>`
  width: 100%;
  padding-inline: 0.2rem;
  background-color: ${p =>
    p.disabled ? p.theme.colors.bg1 : p.theme.colors.bg};
`;

const Select = styled.select`
  cursor: pointer;
  width: 100%;
  border: none;
  outline: none;
  height: 2rem;
  background-color: transparent;
  color: ${p => p.theme.colors.text};
  &:disabled {
    color: ${props => props.theme.colors.textLight};
    background-color: transparent;
  }
`;