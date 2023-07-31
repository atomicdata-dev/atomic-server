import styled, { css } from 'styled-components';

export const FieldStyled = styled.div`
  margin-bottom: ${props => props.theme.margin}rem;
`;

export const LabelWrapper = styled.div`
  display: flex;
  align-items: center;
  margin-bottom: 0.5rem;
`;

export const LabelStyled = styled.label`
  font-weight: bold;
  display: block;
`;

export const LabelHelper = styled.label`
  font-size: 0.9em;
  display: block;
`;

export interface InputWrapperProps {
  invalid?: boolean;
}

/** A wrapper for inputs, for example when you want to add a button to some field */
export const InputWrapper = styled.div<InputWrapperProps>`
  display: flex;
  flex: 1;
  --border-color: ${({ invalid, theme }) =>
    invalid ? theme.colors.alert : theme.colors.bg2};
  border: solid 1px var(--border-color);
  border-radius: ${props => props.theme.radius};
  overflow: hidden;

  &:hover {
    border-color: ${props => props.theme.colors.main};
  }
  &:focus-within {
    border: solid 1px ${props => props.theme.colors.main};
    background-color: ${props => props.theme.colors.bg};
  }
`;

const inputStyle = css`
  height: 2rem;
  flex: 1;
  color: ${props => props.theme.colors.text};
  font-size: 1em;
  padding: ${props => props.theme.margin / 2}rem;
  border: none;
  --webkit-appearance: none;
  /* Remove iOS inner shadow */
  box-shadow: none;
  display: block;
  background-color: ${props => props.theme.colors.bg};
  /* Invisible border, but useful because you need to set :focus styles with Input tags */
  border: solid 1px ${props => props.theme.colors.bg};
  /* border-radius: ${props => props.theme.radius}; */
  outline: none;
  box-sizing: border-box;
  /* If buttons are inside the input, the edges should be sharp */
  border-top-left-radius: ${props => props.theme.radius};
  border-bottom-left-radius: ${props => props.theme.radius};
  transition: border 100ms ease-in-out;

  &:disabled {
    background-color: ${props => props.theme.colors.bg1};
    border-color: ${props => props.theme.colors.bg1};
    color: ${props => props.theme.colors.textLight};
  }

  &:last-child {
    border-radius: ${props => props.theme.radius};
  }
`;

export const InputStyled = styled.input`
  ${inputStyle}
`;

export const TextAreaStyled = styled.textarea`
  ${inputStyle}
  min-height: 5rem;
  height: unset;
`;

export const ErrMessage = styled.div`
  font-size: 0.8em;
  line-height: 1rem;
  color: ${props => props.theme.colors.alert};
  margin-bottom: ${p => p.theme.margin}rem;
`;

export const InlineErrMessage = styled.span`
  font-size: 0.8em;
  line-height: 1rem;
  color: ${props => props.theme.colors.alert};
`;

/** Wraps an inline resource, which is displayed on top of an input */
export const InputOverlay = styled.div`
  ${inputStyle}

  position: absolute;
  pointer-events: none !important;
  /* box-sizing: border-box; */
  border: transparent;
  line-height: 1rem;
  width: 100%;
  border-color: rgba(0, 0, 0, 0);
`;
