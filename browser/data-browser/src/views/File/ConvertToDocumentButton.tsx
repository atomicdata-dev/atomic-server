import { useStore, type Resource } from '@tomic/react';
import { useState, type JSX } from 'react';
import toast from 'react-hot-toast';
import { FaFileLines } from 'react-icons/fa6';
import { Button } from '../../components/Button';
import { Row } from '../../components/Row';
import {
  convertFileToDocument,
  DocumentConversionSaveError,
  getUploadedFileName,
  getConvertibleTextFileKind,
} from './convertFileToDocument';

export function ConvertToDocumentButton({
  resource,
  downloadUrl,
  mimeType,
}: {
  resource: Resource;
  downloadUrl: string;
  mimeType: string;
}): JSX.Element | null {
  const store = useStore();
  const [converting, setConverting] = useState(false);
  const name = getUploadedFileName(resource);
  const convertible = getConvertibleTextFileKind(name, mimeType);

  if (!convertible) {
    return null;
  }

  const handleConvert = async () => {
    setConverting(true);

    try {
      await convertFileToDocument({
        resource,
        store,
        downloadUrl,
        mimeType,
      });
    } catch (error) {
      if (error instanceof DocumentConversionSaveError) {
        toast(
          toastInstance => (
            <Row center gap='0.5rem'>
              <span>Document converted locally, but could not be saved.</span>
              <Button
                subtle
                onClick={() => {
                  resource
                    .save()
                    .then(() => {
                      toast.dismiss(toastInstance.id);
                      toast.success('Document saved');
                    })
                    .catch(() => {
                      toast.error('Could not save the document yet.');
                    });
                }}
              >
                Retry
              </Button>
            </Row>
          ),
          { duration: Infinity, icon: '⚠️' },
        );
      } else {
        toast.error(
          error instanceof Error
            ? error.message
            : 'Could not convert the file.',
        );
      }
    } finally {
      setConverting(false);
    }
  };

  return (
    <Button
      disabled={converting}
      loading={converting ? 'Converting' : undefined}
      onClick={handleConvert}
    >
      <FaFileLines key='convert-document-icon' />
      Convert to document
    </Button>
  );
}
