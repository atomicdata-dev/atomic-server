import { properties } from '@tomic/react';
import React from 'react';
import styled from 'styled-components';
import { ContainerWide } from '../../components/Containers';
import { EditableTitle } from '../../components/EditableTitle';
import { ValueForm } from '../../components/forms/ValueForm';
import { Column, Row } from '../../components/Row';
import { useFileInfo } from '../../hooks/useFile';
import { useMediaQuery } from '../../hooks/useMediaQuery';
import { ResourcePageProps } from '../ResourcePage';
import { DownloadButton, DownloadIconButton } from './DownloadButton';
import { FilePreview } from './FilePreview';

/** Full page File resource for showing and downloading files */
export function FilePage({ resource }: ResourcePageProps) {
  const { downloadFile, bytes } = useFileInfo(resource);
  const wideScreen = useMediaQuery('(min-width: 600px)');

  return (
    <ContainerWide about={resource.getSubject()}>
      <Column gap='2rem'>
        <Row center justify='space-between'>
          <StyledEditableTitle resource={resource} />
          {wideScreen && (
            <DownloadButton downloadFile={downloadFile} fileSize={bytes} />
          )}
          {!wideScreen && (
            <DownloadIconButton downloadFile={downloadFile} fileSize={bytes} />
          )}
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
