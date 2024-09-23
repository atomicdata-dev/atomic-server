import { useState, useEffect } from 'react';
import { styled } from 'styled-components';
import Markdown from '../../components/datatypes/Markdown';

interface TextPreviewProps {
  downloadUrl: string;
  mimeType: string;
  className?: string;
  nestedInLink?: boolean;
}

const fetchFile = async (
  url: string,
  signal: AbortSignal,
  mimeType: string,
) => {
  const res = await fetch(url, {
    credentials: 'include',
    headers: {
      Accept: mimeType,
    },
    signal,
  });

  return res.text();
};

export function TextPreview({
  downloadUrl,
  mimeType,
  className,
  nestedInLink = false,
}: TextPreviewProps): JSX.Element {
  const [data, setData] = useState('');

  useEffect(() => {
    if (!downloadUrl) return;

    const abortController = new AbortController();

    fetchFile(downloadUrl, abortController.signal, mimeType)
      .then(res => setData(res))
      .catch(e => {
        if (e.name !== 'AbortError') throw e;
      });

    return () => abortController.abort();
  }, [downloadUrl]);

  if (mimeType === 'text/markdown') {
    return (
      <div className={className}>
        <Markdown text={data} nestedInLink={nestedInLink} />
      </div>
    );
  }

  return <Wrapper className={className}>{data}</Wrapper>;
}

const Wrapper = styled.pre`
  white-space: pre-wrap;
`;
