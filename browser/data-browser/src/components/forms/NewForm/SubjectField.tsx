import React from 'react';
import Field from '../Field';
import { InputStyled, InputWrapper } from '../InputStyles';

export interface SubjectFieldProps {
  error?: Error;
  value: string;
  onChange: (value: string) => void;
}

export const SubjectField: React.FC<SubjectFieldProps> = ({
  error,
  value,
  onChange,
}) => (
  <Field
    error={error}
    label='subject'
    helper='The identifier of the resource. This also determines where the resource is saved, by default.'
  >
    <InputWrapper>
      <InputStyled
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={'URL of the new resource...'}
      />
    </InputWrapper>
  </Field>
);
