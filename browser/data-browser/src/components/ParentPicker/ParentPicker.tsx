import { styled } from 'styled-components';
import { Column } from '../Row';
import { ParentPickerItem } from './ParentPickerItem';
import { InputStyled, InputWrapper } from '../forms/InputStyles';
import { useSettings } from '../../helpers/AppSettings';
import { FaFolderOpen } from 'react-icons/fa6';

export interface ParentPickerProps {
  root?: string;
  value: string | undefined;
  onChange: (subject: string) => void;
}

export function ParentPicker({
  root,
  value,
  onChange,
}: ParentPickerProps): React.JSX.Element {
  const { drive } = useSettings();

  return (
    <Column>
      <InputWrapper hasPrefix>
        <FaFolderOpen size='1rem' />
        <InputStyled
          placeholder='Enter a subject'
          value={value ?? ''}
          onChange={e => onChange(e.target.value)}
        />
      </InputWrapper>
      <PickerWrapper aria-label='parent selector'>
        <ParentPickerItem
          inialOpen={true}
          subject={root ?? drive}
          onClick={onChange}
          selectedValue={value}
        />
      </PickerWrapper>
    </Column>
  );
}

const PickerWrapper = styled.section`
  background-color: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
  padding: ${p => p.theme.margin}rem;

  height: 20.5rem;
  overflow-y: auto;
`;
