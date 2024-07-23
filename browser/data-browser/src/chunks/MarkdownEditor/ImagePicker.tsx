import {
  NodeViewWrapper,
  ReactNodeViewRenderer,
  type Editor,
} from '@tiptap/react';
import { Image } from '@tiptap/extension-image';
import { styled } from 'styled-components';
import { forwardRef, useState } from 'react';
import { Button } from '../../components/Button';
import { InputStyled, InputWrapper } from '../../components/forms/InputStyles';
import { Column, Row } from '../../components/Row';
import { FilePickerDialog } from '../../components/forms/FilePicker/FilePickerDialog';
import { useStore, type Server } from '@tomic/react';
import {
  ClearType,
  FilePickerButton,
} from '../../components/forms/FilePicker/FilePickerButton';
import { imageMimeTypes } from '../../helpers/filetypes';
import { useHTMLFormFieldValidation } from '../../helpers/useHTMLFormFieldValidation';
import { transition } from '../../helpers/transition';

type PartialImageNodeProps = {
  node: {
    attrs: {
      src?: string;
      alt?: string;
    };
  };
  updateAttributes: (attrs: { src: string; alt?: string }) => void;
  selected: boolean;
  editor: Editor;
};

export const ExtendedImage = Image.extend({
  addNodeView() {
    return ReactNodeViewRenderer(MarkdownEditorImage);
  },
});

const MarkdownEditorImage = forwardRef<
  HTMLImageElement | HTMLDivElement,
  PartialImageNodeProps
>(({ node, updateAttributes, selected, editor }, ref) => {
  const store = useStore();

  const [showPicker, setShowPicker] = useState(false);

  const [urlValue, setUrlValue] = useState<string>();
  const [selectedSubject, setSelectedSubject] = useState<string>();
  const [altText, setAltText] = useState<string>();

  const [urlValid, urlRef] = useHTMLFormFieldValidation();

  const canSave = () => {
    if (selectedSubject) {
      return true;
    }

    return urlValid;
  };

  const save = async () => {
    if (selectedSubject) {
      const resource = await store.getResource<Server.File>(selectedSubject);
      updateAttributes({ src: resource.props.downloadUrl, alt: altText });
    } else if (urlValue) {
      updateAttributes({ src: urlValue, alt: altText });
    }

    editor.chain().focus().run();
  };

  if (node.attrs.src) {
    return (
      <NodeViewWrapper>
        <StyledImage
          ref={ref as React.ForwardedRef<HTMLImageElement>}
          src={node.attrs.src}
          alt=''
          selected={selected}
        />
      </NodeViewWrapper>
    );
  }

  return (
    <NodeViewWrapper>
      <Wrapper ref={ref} selected={selected}>
        <Column justify='flex-start'>
          <ColumnGrid>
            <Column>
              {!selectedSubject && (
                <>
                  <StyledInputWrapper>
                    <InputStyled
                      autoFocus
                      ref={urlRef}
                      type='url'
                      required
                      placeholder='Enter a URL...'
                      value={urlValue}
                      onChange={e => setUrlValue(e.target.value)}
                    />
                  </StyledInputWrapper>
                  <span>Or</span>
                </>
              )}
              <FilePickerButton
                onButtonClick={() => setShowPicker(true)}
                subject={selectedSubject}
                onClear={clearType => {
                  if (clearType === ClearType.Subject) {
                    setSelectedSubject(undefined);
                  }
                }}
              />
            </Column>
            <TextArea
              placeholder='Alt text'
              value={altText}
              onChange={e => setAltText(e.target.value)}
            />
          </ColumnGrid>
          <Row justify='flex-end'>
            <Button disabled={!canSave()} onClick={save}>
              Save
            </Button>
          </Row>
        </Column>
      </Wrapper>
      <FilePickerDialog
        noUpload
        show={showPicker}
        onShowChange={setShowPicker}
        onResourcePicked={setSelectedSubject}
        onNewFilePicked={() => undefined}
        allowedMimes={imageMimeTypes}
      />
    </NodeViewWrapper>
  );
});

MarkdownEditorImage.displayName = 'MarkdownEditorImage';

type SelectableProps = {
  selected: boolean;
};

const StyledImage = styled.img<SelectableProps>`
  max-width: 100%;
  height: auto;
  border-radius: ${p => p.theme.radius};
  margin-bottom: ${p => p.theme.margin}rem;
  ${transition('box-shadow', 'filter')}

  .tiptap:focus-within & {
    box-shadow: 0 0 0 2px
      ${p => (p.selected ? p.theme.colors.main : 'transparent')};
    filter: ${p => (p.selected ? 'brightness(0.9)' : 'none')};
  }
`;

const Wrapper = styled.div<SelectableProps>`
  border: 2px dashed
    ${p => (p.selected ? p.theme.colors.main : p.theme.colors.bg2)};
  border-radius: ${p => p.theme.radius};
  padding: ${p => p.theme.margin}rem;
  margin-bottom: ${p => p.theme.margin}rem;
`;

const ColumnGrid = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: ${p => p.theme.margin}rem;
`;

const TextArea = styled.textarea`
  width: 100%;
  color: ${p => p.theme.colors.text};
  background-color: ${p => p.theme.colors.bg};
  padding: ${p => p.theme.margin / 2}rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
  font-size: 1rem;
  font-family: inherit;
  resize: vertical;
  min-height: 5rem;
`;

const StyledInputWrapper = styled(InputWrapper)`
  flex: unset;
  &:has(:user-invalid) {
    border-color: ${p => p.theme.colors.alert} !important;
  }
`;
