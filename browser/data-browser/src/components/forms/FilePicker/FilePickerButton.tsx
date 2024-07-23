import { FaFileCirclePlus } from 'react-icons/fa6';
import { Button } from '../../Button';
import { SelectedFileResource, SelectedFileBlob } from './SelectedFile';

export enum ClearType {
  File = 'file',
  Subject = 'subject',
}

interface FilePickerInputProps {
  subject?: string;
  file?: File;
  disabled?: boolean;
  onButtonClick: () => void;
  onClear: (clearType: ClearType) => void;
}

export function FilePickerButton({
  subject,
  file,
  disabled,
  onButtonClick,
  onClear,
}: FilePickerInputProps): React.JSX.Element {
  return (
    <>
      {!file && !subject && (
        <Button subtle onClick={onButtonClick} disabled={disabled}>
          <FaFileCirclePlus />
          Select File
        </Button>
      )}
      {subject && (
        <SelectedFileResource
          disabled={disabled}
          subject={subject}
          onClear={() => onClear(ClearType.Subject)}
        />
      )}
      {file && (
        <SelectedFileBlob
          file={file}
          disabled={disabled}
          onClear={() => onClear(ClearType.File)}
        />
      )}
    </>
  );
}
