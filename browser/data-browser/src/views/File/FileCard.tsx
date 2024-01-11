import { useMemo } from 'react';
import { AtomicLink } from '../../components/AtomicLink';
import { Row } from '../../components/Row';
import { useFileInfo } from '../../hooks/useFile';
import { CardViewProps } from '../Card/CardViewProps';
import { ResourceCardTitle } from '../Card/ResourceCardTitle';
import { ErrorBoundary } from '../ErrorPage';
import { DownloadIconButton } from './DownloadButton';
import { FilePreview } from './FilePreview';

function FileCard(props: CardViewProps): JSX.Element {
  const FileError = useMemo(() => {
    const Temp = () => {
      return (
        <>
          <AtomicLink subject={props.resource.getSubject()}>
            {props.resource.title}
          </AtomicLink>
          <div>Can not show file due to invalid data.</div>
        </>
      );
    };

    Temp.displayName = 'FileError';

    return Temp;
  }, [props.resource.getSubject(), props.resource.title]);

  return (
    <ErrorBoundary FallBackComponent={FileError}>
      <FileCardInner {...props} />
    </ErrorBoundary>
  );
}

export default FileCard;

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
