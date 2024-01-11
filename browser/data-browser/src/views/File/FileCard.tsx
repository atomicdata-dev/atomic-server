import { Row } from '../../components/Row';
import { useFileInfo } from '../../hooks/useFile';
import { CardViewProps } from '../Card/CardViewProps';
import { ResourceCardTitle } from '../Card/ResourceCardTitle';
import { ErrorBoundary } from '../ErrorPage';
import { DownloadIconButton } from './DownloadButton';
import { FilePreview } from './FilePreview';

function FileCard(props: CardViewProps): JSX.Element {
  return (
    <ErrorBoundary FallBackComponent={FileError}>
      <FileCardInner {...props} />
    </ErrorBoundary>
  );
}

export default FileCard;

const FileError = () => {
  return <div>Can not show file due to invalid data.</div>;
};

function FileCardInner({ resource }: CardViewProps): JSX.Element {
  const { downloadFile, bytes } = useFileInfo(resource);

  return (
    <>
      <Row justify='space-between'>
        <ResourceCardTitle resource={resource} />
        <DownloadIconButton downloadFile={downloadFile} fileSize={bytes} />
      </Row>
      <FilePreview resource={resource} hideTypes={['application/pdf']} />
    </>
  );
}
