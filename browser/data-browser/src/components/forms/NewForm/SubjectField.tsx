import { useState } from 'react';
import Field from '../Field';
import { InputStyled, InputWrapper } from '../InputStyles';
import { styled } from 'styled-components';

export interface SubjectFieldProps {
  error?: Error;
  value: string;
  onChange: (value: string) => void;
}

const getPath = (value: string) => {
  const url = new URL(value);

  const path = url.pathname.slice(1);

  return [url.origin + '/', path];
};

const normalizePath = (str: string) => {
  if (str.startsWith('/')) {
    return normalizePath(str.slice(1));
  }

  return '/' + str;
};

export function SubjectField({ error, value, onChange }: SubjectFieldProps) {
  const [origin, path] = getPath(value);
  const [inputValue, setInputValue] = useState(path);

  const handleChange = (v: string) => {
    const subject = new URL(normalizePath(v), value);
    setInputValue(subject.pathname.slice(1));
    onChange(subject.toString());
  };

  return (
    <Field
      error={error}
      label='subject'
      helper='The identifier of the resource. This also determines where the resource is saved, by default.'
    >
      <InputWrapper>
        <OriginPart>{origin}</OriginPart>
        <StyledInputStyled
          value={inputValue}
          onChange={e => handleChange(e.target.value)}
          placeholder={'URL of the new resource...'}
        />
      </InputWrapper>
    </Field>
  );
}

const OriginPart = styled.span`
  height: 2rem;
  display: flex;
  align-items: center;
  padding-inline: 0.5rem;
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.textLight};
`;

const StyledInputStyled = styled(InputStyled)`
  && {
    border-radius: 0;
  }
`;
