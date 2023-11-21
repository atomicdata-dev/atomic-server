import { useState, useEffect } from 'react';
import { styled } from 'styled-components';
import Markdown from '../../components/datatypes/Markdown';

interface TextPreviewProps {
  downloadUrl: string;
  mimeType: string;
  className?: string;
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
}: TextPreviewProps): JSX.Element {
  const [data, setData] = useState('');

  useEffect(() => {
    const abortController = new AbortController();

    fetchFile(downloadUrl, abortController.signal, mimeType).then(res =>
      setData(res),
    );

    return () => abortController.abort();
  }, [downloadUrl]);

  if (mimeType === 'text/markdown') {
    return (
      <div className={className}>
        <Markdown text={data} />
      </div>
    );
  }

  return <Wrapper className={className}>{data}</Wrapper>;
}

const Wrapper = styled.pre`
  white-space: pre-wrap;
`;
