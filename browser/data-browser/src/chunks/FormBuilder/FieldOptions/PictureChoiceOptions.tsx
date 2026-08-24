import { Resource, server, useResource, type JSONValue } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaImage, FaPlus, FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { Button } from '@components/Button';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Column, Row } from '@components/Row';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
import { FilePickerDialog } from '@components/forms/FilePicker/FilePickerDialog';
import { useUpload } from '../../../hooks/useUpload';
import { useDebounce } from '@helpers/useDebounce';
import { AddButton } from './StringListEditor';
import { useFieldOptions } from './useFieldOptions';

const IMAGE_MIMES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
  'image/svg+xml',
]);

interface PictureChoiceOptionsProps {
  field: Resource;
}

interface Draft {
  options: string[];
  images: string[];
}

/**
 * Options for a `picture-choice` question: a label plus an image per choice.
 * Images are File subjects stored in `optionImages`, positionally matched to
 * `options` — so renaming a label keeps its image. Labels and images share one
 * debounced draft: they live in the same JSON property, and writing them from
 * two places would let one write clobber the other's pending edit.
 */
export function PictureChoiceOptions({
  field,
}: PictureChoiceOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);
  const { upload, isUploading } = useUpload(field);

  const stored: Draft = {
    options: (options.options as string[] | undefined) ?? [],
    images: (options.optionImages as string[] | undefined) ?? [],
  };

  const [draft, setDraft] = useState<Draft>(stored);
  const debounced = useDebounce(draft, 150);
  const [pickingFor, setPickingFor] = useState<number | undefined>();

  useEffect(() => {
    setDraft(stored);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [field.subject]);

  useEffect(() => {
    if (JSON.stringify(debounced) !== JSON.stringify(stored)) {
      setOptions({
        ...options,
        options: debounced.options,
        optionImages: debounced.images as JSONValue,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  const setImage = (index: number, subject: string) => {
    const images = [...draft.images];
    images[index] = subject;
    setDraft({ ...draft, images });
    setPickingFor(undefined);
  };

  const handleUpload = async (file: File) => {
    const index = pickingFor;

    if (index === undefined) return;

    const [subject] = await upload([file]);

    if (subject) {
      setImage(index, subject);
    }
  };

  return (
    <>
      <Field label='Options'>
        <Column gap='0.6rem'>
          {draft.options.map((option, index) => (
            <OptionRow key={`option-${index}`} gap='0.5rem' center>
              <OptionImage subject={draft.images[index]} />
              <Column gap='0.3rem'>
                <InputWrapper>
                  <InputStyled
                    data-testid='picture-option-input'
                    value={option}
                    onChange={e => {
                      const next = [...draft.options];
                      next[index] = e.target.value;
                      setDraft({ ...draft, options: next });
                    }}
                  />
                </InputWrapper>
                <Row gap='0.3rem'>
                  <Button
                    subtle
                    type='button'
                    disabled={isUploading}
                    onClick={() => setPickingFor(index)}
                  >
                    <FaImage /> {draft.images[index] ? 'Replace' : 'Add image'}
                  </Button>
                  <IconButton
                    variant={IconButtonVariant.Simple}
                    size='0.8rem'
                    color='textLight'
                    title='Remove option'
                    type='button'
                    onClick={() =>
                      setDraft({
                        options: draft.options.filter((_, i) => i !== index),
                        images: draft.images.filter((_, i) => i !== index),
                      })
                    }
                  >
                    <FaTrash />
                  </IconButton>
                </Row>
              </Column>
            </OptionRow>
          ))}
          <AddButton
            type='button'
            subtle
            onClick={() =>
              setDraft({
                options: [
                  ...draft.options,
                  `Option ${draft.options.length + 1}`,
                ],
                images: [...draft.images, ''],
              })
            }
          >
            <Row gap='.5rem' center>
              <FaPlus /> Add option
            </Row>
          </AddButton>
        </Column>
      </Field>
      <FilePickerDialog
        show={pickingFor !== undefined}
        onShowChange={show => !show && setPickingFor(undefined)}
        onResourcePicked={subject => setImage(pickingFor ?? 0, subject)}
        onNewFilePicked={handleUpload}
        allowedMimes={IMAGE_MIMES}
      />
    </>
  );
}

/** Thumbnail of the picked File. The builder is authenticated, so the File's
 * rights-checked `downloadURL` works here — the published form instead gets
 * the publish-gated `/form/{id}/image?file=…` URL from the server. */
function OptionImage({ subject }: { subject?: string }): JSX.Element {
  const file = useResource(subject);
  const url = subject
    ? (file.get(server.properties.downloadUrl) as string | undefined)
    : undefined;

  return url ? (
    <Thumbnail src={url} alt='' />
  ) : (
    <EmptyThumbnail>
      <FaImage />
    </EmptyThumbnail>
  );
}

const OptionRow = styled(Row)`
  align-items: flex-start;
`;

const Thumbnail = styled.img`
  width: 3.5rem;
  height: 3.5rem;
  object-fit: cover;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
`;

const EmptyThumbnail = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 3.5rem;
  height: 3.5rem;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.textLight};
`;
