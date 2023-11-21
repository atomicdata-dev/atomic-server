import { useTitle } from '@tomic/react';

import { AtomicLink } from '../../components/AtomicLink';
import { Row } from '../../components/Row';
import { useFileInfo } from '../../hooks/useFile';
import { CardViewProps } from '../Card/CardViewProps';
import { DownloadIconButton } from './DownloadButton';
import { FilePreview } from './FilePreview';

function FileCard({ resource }: CardViewProps): JSX.Element {
  const [title] = useTitle(resource);
  const { downloadFile, bytes } = useFileInfo(resource);

  return (
    <>
      <Row justify='space-between'>
        <AtomicLink subject={resource.getSubject()}>
          <h2>{title}</h2>
        </AtomicLink>
        <DownloadIconButton downloadFile={downloadFile} fileSize={bytes} />
      </Row>
      <FilePreview resource={resource} />
    </>
  );
}

export default FileCard;
