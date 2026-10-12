import {
  forms,
  Resource,
  server,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import { useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaImage } from 'react-icons/fa6';
import { Button } from '@components/Button';
import { Row } from '@components/Row';
import { FilePickerDialog } from '@components/forms/FilePicker/FilePickerDialog';
import { useUpload } from '../../../hooks/useUpload';
import { LinkableTagList } from './LinkableTagList';

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

/**
 * Options for a `picture-choice` question: the same label list every choice
 * question has ({@link LinkableTagList}), plus a thumbnail and an image picker
 * per row.
 *
 * The image is the option Tag's `cover-image`, so an option is one resource
 * rather than a label and an image held in two positionally matched arrays.
 */
export function PictureChoiceOptions({
  field,
}: PictureChoiceOptionsProps): JSX.Element {
  const store = useStore();
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo);
  const { upload, isUploading } = useUpload(field);

  const [pickingFor, setPickingFor] = useState<string | undefined>();

  const setImage = async (tagSubject: string, fileSubject: string) => {
    const tag = await store.getResource(tagSubject);
    await tag.set(forms.properties.coverImage, fileSubject);
    await tag.save();
    setPickingFor(undefined);
  };

  const handleUpload = async (file: File) => {
    const tagSubject = pickingFor;

    if (tagSubject === undefined) return;

    const [subject] = await upload([file]);

    if (subject) {
      await setImage(tagSubject, subject);
    }
  };

  // Only while the field's mapped Property is still loading — every saved
  // choice field has one.
  if (!mapsTo) {
    return <></>;
  }

  return (
    <>
      <LinkableTagList
        field={field}
        property={property}
        label='Options'
        addLabel='Add option'
        removeLabel='Remove option'
        itemTestId='picture-option-input'
        leading={subject => <TagImage subject={subject} />}
        belowInput={subject => (
          <Row>
            <Button
              subtle
              type='button'
              disabled={isUploading}
              onClick={() => setPickingFor(subject)}
            >
              <FaImage /> <ImageButtonLabel subject={subject} />
            </Button>
          </Row>
        )}
      />
      <FilePickerDialog
        show={pickingFor !== undefined}
        onShowChange={show => !show && setPickingFor(undefined)}
        onResourcePicked={subject =>
          pickingFor !== undefined && setImage(pickingFor, subject)
        }
        onNewFilePicked={handleUpload}
        allowedMimes={IMAGE_MIMES}
      />
    </>
  );
}

function ImageButtonLabel({ subject }: { subject: string }): JSX.Element {
  const tag = useResource(subject);

  return <>{tag.get(forms.properties.coverImage) ? 'Replace' : 'Add image'}</>;
}

/** Thumbnail of the option Tag's cover image. The builder is authenticated, so
 * the File's rights-checked `downloadURL` works here — the published form
 * instead gets the publish-gated `/form/{id}/image?file=…` URL from the
 * server. */
function TagImage({ subject }: { subject: string }): JSX.Element {
  const tag = useResource(subject);
  const fileSubject = tag.get(forms.properties.coverImage) as
    | string
    | undefined;
  const file = useResource(fileSubject);
  const url = fileSubject
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
