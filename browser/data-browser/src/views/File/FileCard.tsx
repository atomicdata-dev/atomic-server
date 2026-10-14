import { useMemo, type JSX } from 'react';
import { AtomicLink } from '../../components/AtomicLink';
import { Column } from '../../components/Row';
import { useFileInfo } from '../../hooks/useFile';
import { CardViewProps } from '../Card/CardViewProps';
import { ResourceCardTitle } from '../Card/ResourceCardTitle';
import { ErrorBoundary } from '../ErrorPage';
import { DownloadIconButton } from './DownloadButton';
import { FilePreview } from './FilePreview';
import { SimpleTagBar } from '../../components/Tag/TagBar';

function FileCard(props: CardViewProps): JSX.Element {
  const FileError = useMemo(() => {
    const Temp = () => {
      return (
        <>
          <AtomicLink subject={props.resource.subject}>
            {props.resource.title}
          </AtomicLink>
          <div>Can not show file due to invalid data.</div>
        </>
      );
    };

    return Temp;
  }, [props.resource.subject, props.resource.title]);

  return (
    <ErrorBoundary FallBackComponent={FileError}>
      <FileCardInner {...props} />
    </ErrorBoundary>
  );
}

export default FileCard;

function FileCardInner({ resource }: CardViewProps): JSX.Element {
  const { downloadFile, bytes, loading } = useFileInfo(resource);

  return (
    <Column gap='1rem'>
      <ResourceCardTitle resource={resource}>
        <DownloadIconButton
          downloadFile={downloadFile}
          fileSize={bytes}
          disabled={loading}
        />
      </ResourceCardTitle>
      <SimpleTagBar small resource={resource} />
      <FilePreview resource={resource} hideTypes={['application/pdf']} />
    </Column>
  );
}
