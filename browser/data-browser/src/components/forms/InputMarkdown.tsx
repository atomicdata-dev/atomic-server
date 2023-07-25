import React, { useState } from 'react';
import { useString } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage, InputWrapper } from './InputStyles';
import Yamde from 'yamde';
import { useSettings } from '../../helpers/AppSettings';
import styled from 'styled-components';

export default function InputMarkdown({
  resource,
  property,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [value, setVale] = useString(resource, property.subject, {
    handleValidationError: setErr,
  });
  const { darkMode } = useSettings();

  return (
    <>
      <InputWrapper>
        <YamdeStyling>
          <Yamde
            value={value ? value : ''}
            handler={e => setVale(e)}
            theme={darkMode ? 'dark' : 'light'}
            required={false}
            {...props}
          />
        </YamdeStyling>
        {/* <TextAreaStyled rows={3} value={value === null ? '' : value} onChange={handleUpdate} required={required} autoFocus={autoFocus} /> */}
      </InputWrapper>
      {value !== '' && err && <ErrMessage>{err.message}</ErrMessage>}
      {value === '' && <ErrMessage>Required</ErrMessage>}
    </>
  );
}

const YamdeStyling = styled.div`
  display: flex;
  flex: 1;

  .yamde-0-2-1 {
    margin: 0;
  }

  .contentArea-0-2-8 textarea,
  .preview-0-2-9 {
    background: ${p => p.theme.colors.bg};
    font-size: ${p => p.theme.fontSizeBody}rem;
  }
`;
