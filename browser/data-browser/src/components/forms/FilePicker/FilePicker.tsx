import { useEffect, useState } from 'react';
import { Button } from '../../Button';
import { FilePickerDialog } from './FilePickerDialog';
import { SelectedFileBlob, SelectedFileResource } from './SelectedFile';
import { InputProps } from '../ResourceField';
import { FaFileCirclePlus } from 'react-icons/fa6';
import { StoreEvents, useStore, useSubject } from '@tomic/react';
import { useUpload } from '../../../hooks/useUpload';
import { VisuallyHidden } from '../../VisuallyHidden';
import { styled } from 'styled-components';

/**
 * Button that opens a dialog that lists all files in the drive and allows the user to upload a new file.
 * Handles uploads and makes sure files are uploaded even when the parent resource is not saved yet.
 */
export function FilePicker({
  resource,
  property,
  disabled,
  required,
  commit,
}: InputProps): React.JSX.Element {
  const store = useStore();
  const { upload } = useUpload(resource);
  const [value, setValue] = useSubject(resource, property.subject, {
    validate: false,
    commit: commit,
  });
  const [show, setShow] = useState(false);
  const [selectedSubject, setSelectedSubject] = useState<string | undefined>(
    value,
  );
  const [selectedFile, setSelectedFile] = useState<File | undefined>();

  const [unsubScheduledUpload, setUnsubScheduledUpload] =
    useState<() => void | undefined>();

  useEffect(() => {
    if (selectedSubject) {
      setValue(selectedSubject);
    } else if (selectedFile) {
      if (resource.new) {
        // We can't upload the file yet because its parent has not saved yet so we set the value to a placeholder and then schedule an upload when the resource is saved.
        setValue('https://placeholder');
        setUnsubScheduledUpload(prevUnsub => {
          prevUnsub?.();

          const thisUnsub = store.on(
            StoreEvents.ResourceSaved,
            async savedResource => {
              if (savedResource.getSubject() === resource.getSubject()) {
                thisUnsub();
                const [subject] = await upload([selectedFile]);
                await setValue(subject);
                resource.save(store);
              }
            },
          );

          return thisUnsub;
        });
      } else {
        upload([selectedFile]).then(([subject]) => {
          setValue(subject);
        });
      }
    } else {
      setValue(undefined);
    }
  }, [selectedSubject, selectedFile]);

  return (
    <Wrapper>
      <VisuallyHidden>
        {value}
        <input
          aria-hidden
          type='text'
          value={value ?? ''}
          required={required}
          disabled={disabled}
        />
      </VisuallyHidden>
      {!selectedFile && !selectedSubject && (
        <Button subtle onClick={() => setShow(true)} disabled={disabled}>
          <FaFileCirclePlus />
          Select File
        </Button>
      )}
      {selectedSubject && (
        <SelectedFileResource
          disabled={disabled}
          subject={selectedSubject}
          onClear={() => setSelectedSubject(undefined)}
        />
      )}
      {selectedFile && (
        <SelectedFileBlob
          file={selectedFile}
          disabled={disabled}
          onClear={() => {
            setSelectedFile(undefined);
            unsubScheduledUpload?.();
          }}
        />
      )}
      <FilePickerDialog
        show={show}
        onShowChange={setShow}
        onResourcePicked={setSelectedSubject}
        onNewFilePicked={setSelectedFile}
      />
    </Wrapper>
  );
}

const Wrapper = styled.div`
  position: relative;
`;
