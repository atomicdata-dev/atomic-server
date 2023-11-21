import { useState } from 'react';
import { useString } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage, InputWrapper } from './InputStyles';
import Yamde from 'yamde';
import { useSettings } from '../../helpers/AppSettings';
import { styled } from 'styled-components';

export default function InputMarkdown({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const { darkMode } = useSettings();

  const [err, setErr] = useState<Error | undefined>(undefined);
  const [value, setValue] = useString(resource, property.subject, {
    handleValidationError: setErr,
    commit: commit,
  });

  // We keep a local value that does not update when value is update by anything but the user because the Yamde editor resets cursor position when that happens.
  const [localValue, setLocalValue] = useState(value ?? '');

  const handleChange = (val: string) => {
    setLocalValue(val);
    setValue(val);
  };

  return (
    <>
      <InputWrapper>
        <YamdeStyling>
          <Yamde
            value={localValue}
            handler={handleChange}
            theme={darkMode ? 'dark' : 'light'}
            required={false}
            {...props}
          />
        </YamdeStyling>
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
    border: none;
    border-top: 1px solid ${p => p.theme.colors.bg2};

    &:focus {
      border: none;
      border-top: 1px solid ${p => p.theme.colors.bg2};
    }
  }
  .buttons-0-2-3 {
    width: 100%;
  }

  .button-0-2-10 {
    background-color: ${p => p.theme.colors.bgBody};
    width: unset;
    margin-right: unset;
    flex: 1;
    border: unset;
    border-right: 1px solid ${p => p.theme.colors.bg2};

    &:last-of-type {
      border-right: unset;
    }
  }

  .viewButton-0-2-6:last-of-type {
    border-right: unset;
  }
`;
