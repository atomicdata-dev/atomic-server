import { properties, useCanWrite } from '@tomic/react';

import { styled } from 'styled-components';
import { ContainerWide } from '../../components/Containers';
import { EditableTitle } from '../../components/EditableTitle';
import { ValueForm } from '../../components/forms/ValueForm';
import { Column, Row } from '../../components/Row';
import { useFileInfo } from '../../hooks/useFile';
import { useMediaQuery } from '../../hooks/useMediaQuery';
import { ResourcePageProps } from '../ResourcePage';
import { DownloadButton, DownloadIconButton } from './DownloadButton';
import { ConvertToDocumentButton } from './ConvertToDocumentButton';
import { FilePreview } from './FilePreview';

/** Full page File resource for showing and downloading files */
export function FilePage({ resource }: ResourcePageProps) {
  const { downloadFile, downloadUrl, bytes, mimeType, loading } =
    useFileInfo(resource);
  const canWrite = useCanWrite(resource);
  const wideScreen = useMediaQuery('(min-width: 600px)');

  return (
    <ContainerWide>
      <Column gap='2rem'>
        <Row center justify='space-between'>
          <StyledEditableTitle resource={resource} />
          <Row center gap='0.5rem' wrapItems>
            {wideScreen && (
              <DownloadButton
                downloadFile={downloadFile}
                fileSize={bytes}
                disabled={loading}
              />
            )}
            {!wideScreen && (
              <DownloadIconButton
                disabled={loading}
                downloadFile={downloadFile}
                fileSize={bytes}
              />
            )}
            {canWrite && !loading && (
              <ConvertToDocumentButton
                resource={resource}
                downloadUrl={downloadUrl}
                mimeType={mimeType}
              />
            )}
          </Row>
        </Row>
        <ValueForm resource={resource} propertyURL={properties.description} />
        <FilePreview resource={resource} />
      </Column>
    </ContainerWide>
  );
}

const StyledEditableTitle = styled(EditableTitle)`
  margin: 0;
`;
