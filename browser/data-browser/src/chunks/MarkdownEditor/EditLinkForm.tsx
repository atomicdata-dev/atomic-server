import { Button } from '../../components/Button';
import { Column, Row } from '../../components/Row';
import { InputWrapper, InputStyled } from '../../components/forms/InputStyles';
import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { useTipTapEditor } from './TiptapContext';
import { useHTMLFormFieldValidation } from '../../helpers/useHTMLFormFieldValidation';

interface EditLinkFormProps {
  onDone: () => void;
}

export function EditLinkForm({ onDone }: EditLinkFormProps): React.JSX.Element {
  const [href, setHref] = useState('');

  const editor = useTipTapEditor();
  const [linkValid, linkRef] = useHTMLFormFieldValidation();

  useEffect(() => {
    if (!editor) return;

    setHref(editor.getAttributes('link').href);
  }, [editor]);

  const setLink = () => {
    if (!editor) return;

    editor.chain().focus().extendMarkRange('link').setLink({ href }).run();
    onDone();
  };

  const removeLink = () => {
    if (!editor) return;

    editor.chain().focus().unsetLink().run();
    onDone();
  };

  if (!editor) return <></>;

  return (
    <Column>
      <StyledInputWrapper>
        <InputStyled
          ref={linkRef}
          type='url'
          required
          value={href}
          onChange={e => setHref(e.target.value)}
          placeholder='https://example.com'
        />
      </StyledInputWrapper>
      <Row justify='end'>
        <Button subtle disabled={!editor.isActive('link')} onClick={removeLink}>
          Remove
        </Button>
        <Button onClick={setLink} disabled={!linkValid}>
          Set
        </Button>
      </Row>
    </Column>
  );
}

const StyledInputWrapper = styled(InputWrapper)`
  &:has(:user-invalid) {
    border-color: ${p => p.theme.colors.alert} !important;
  }
`;
