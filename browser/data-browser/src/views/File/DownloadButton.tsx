import React from 'react';
import { FaDownload } from 'react-icons/fa';
import styled from 'styled-components';
import { Button } from '../../components/Button';
import { IconButton } from '../../components/IconButton/IconButton';
import { Row } from '../../components/Row';
import { displayFileSize } from './displayFileSize';

interface DownloadButtonProps {
  downloadFile: () => void;
  fileSize?: number;
}

export function DownloadIconButton({
  downloadFile,
  fileSize,
}: DownloadButtonProps): JSX.Element {
  return (
    <IconButton
      title={`Download file (${displayFileSize(fileSize ?? 0)})`}
      onClick={downloadFile}
    >
      <DownloadIcon />
    </IconButton>
  );
}

const DownloadIcon = styled(FaDownload)`
  color: ${({ theme }) => theme.colors.main};
`;

export function DownloadButton({
  downloadFile,
  fileSize,
}: DownloadButtonProps): JSX.Element {
  return (
    <StyledButton
      onClick={downloadFile}
      title={`Download file (${displayFileSize(fileSize ?? 0)})`}
    >
      <Row gap='0.5rem'>
        <FaDownload />
        Download
      </Row>
    </StyledButton>
  );
}

const StyledButton = styled(Button)`
  view-transition-name: download-button;
`;
