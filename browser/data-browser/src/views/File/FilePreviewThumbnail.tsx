import { Resource } from '@tomic/react';
import { FaTriangleExclamation } from 'react-icons/fa6';
import { useFilePreviewSizeLimit } from '../../hooks/useFilePreviewSizeLimit';
import { useFileImageTransitionStyles } from './useFileImageTransitionStyles';
import { useFileInfo } from '../../hooks/useFile';
import { Thumbnail } from '../../components/Thumbnail';
import { isImageFile, isTextFile } from './fileTypeUtils';
import { styled } from 'styled-components';
import { InnerWrapper } from '../FolderPage/GridItem/components';
import { TextPreview } from './TextPreview';
import { ErrorBoundary } from '../ErrorPage';
import { Row } from '../../components/Row';

interface FilePreviewThumbnailProps {
  resource: Resource;
}

export function FilePreviewThumbnail(
  props: FilePreviewThumbnailProps,
): JSX.Element {
  return (
    <ErrorBoundary
      FallBackComponent={() => (
        <TextWrapper error>
          <Row gap='1ch' center>
            <FaTriangleExclamation />
            Could not display file preview.
          </Row>
        </TextWrapper>
      )}
    >
      <FilePreviewThumbnailInner {...props} />
    </ErrorBoundary>
  );
}

function FilePreviewThumbnailInner({
  resource,
}: FilePreviewThumbnailProps): JSX.Element {
  const { downloadUrl, mimeType, bytes } = useFileInfo(resource);
  const previewSizeLimit = useFilePreviewSizeLimit();
  const transitionStyles = useFileImageTransitionStyles(resource.subject);

  if (bytes >= previewSizeLimit) {
    return <TextWrapper>To large for preview</TextWrapper>;
  }

  if (isImageFile(mimeType)) {
    return <Thumbnail subject={resource.subject} style={transitionStyles} />;
  }

  if (isTextFile(mimeType)) {
    return <StyledTextPreview downloadUrl={downloadUrl} mimeType={mimeType} />;
  }

  return <TextWrapper>No preview available</TextWrapper>;
}

const TextWrapper = styled(InnerWrapper)<{ error?: boolean }>`
  display: grid;
  place-items: center;
  color: ${p => (p.error ? p.theme.colors.alert : p.theme.colors.textLight)};
`;

const StyledTextPreview = styled(TextPreview)`
  padding: ${p => p.theme.margin}rem;
  color: ${p => p.theme.colors.textLight};

  &:is(pre) {
    padding: 0;
    padding-inline: ${p => p.theme.margin}rem;
  }
`;
