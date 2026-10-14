import { FaDownload } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Button } from '../../components/Button';
import { IconButton } from '../../components/IconButton/IconButton';
import { Row } from '../../components/Row';
import { displayFileSize } from './displayFileSize';

import type { JSX } from 'react';

interface DownloadButtonProps {
  downloadFile: () => void;
  fileSize?: number;
  disabled?: boolean;
}

export function DownloadIconButton({
  downloadFile,
  fileSize,
  disabled,
}: DownloadButtonProps): JSX.Element {
  return (
    <IconButton
      title={`Download file (${displayFileSize(fileSize ?? 0)})`}
      disabled={disabled}
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
  disabled,
}: DownloadButtonProps): JSX.Element {
  return (
    <StyledButton
      disabled={disabled}
      onClick={downloadFile}
      title={`Download file (${displayFileSize(fileSize ?? 0)})`}
    >
      <Row gap='0.5rem'>
        <FaDownload />
        <span>Download</span>
      </Row>
    </StyledButton>
  );
}

const StyledButton = styled(Button)`
  view-transition-name: download-button;
`;
