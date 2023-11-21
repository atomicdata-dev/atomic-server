import { useCallback, useMemo, useState } from 'react';
import { pdfjs, Document, Page } from 'react-pdf';
import 'react-pdf/dist/esm/Page/TextLayer.css';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import { styled } from 'styled-components';

pdfjs.GlobalWorkerOptions.workerSrc = `https://unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.js`;
interface PDFViewerProps {
  url: string;
  className?: string;
}

export default function PDFViewer({
  url,
  className,
}: PDFViewerProps): JSX.Element {
  const [numberOfPages, setNumberOfPages] = useState<number>(0);
  const handleError = useCallback((error: Error) => console.error(error), []);

  const handleDocumentLoadSuccess = useCallback(
    ({ numPages }: { numPages: number }) => {
      setNumberOfPages(numPages);
    },
    [],
  );

  const file = useMemo(() => {
    return {
      url: url,
      withCredentials: true,
    };
  }, [url]);

  return (
    <StyledDocument
      file={file}
      className={className}
      onLoadSuccess={handleDocumentLoadSuccess}
      onLoadError={handleError}
      onSourceError={handleError}
    >
      {Array.from(new Array(numberOfPages), (el, index) => (
        <StyledPage key={`page_${index + 1}`} pageNumber={index + 1} />
      ))}
    </StyledDocument>
  );
}

const StyledDocument = styled(Document)`
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 100%;
  overflow-x: auto;
  overflow-y: visible;
  padding-bottom: 1rem;
`;

const StyledPage = styled(Page)`
  margin: auto;
  border-radius: ${({ theme }) => theme.radius};
  overflow: hidden;
  box-shadow: ${({ theme }) => theme.boxShadow};
`;
