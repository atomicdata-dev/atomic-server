import React from 'react';
import styled from 'styled-components';
import { ContainerNarrow } from '../../components/Containers.jsx';
import Markdown from '../../components/datatypes/Markdown.jsx';
import { ErrorLook } from '../../components/ErrorLook';

export interface BookmarkPreviewProps {
  preview: string;
  error?: Error;
  loading?: boolean;
}

export function BookmarkPreview({
  preview,
  error,
  loading,
}: BookmarkPreviewProps): JSX.Element {
  if (loading) {
    return <CenterGrid>loading...</CenterGrid>;
  }

  if (error) {
    return <ErrorPage error={error} />;
  }

  if (!preview || preview === '') {
    return <CenterGrid>no preview...</CenterGrid>;
  }

  return (
    <StyledContainerNarrow>
      <Markdown renderGFM text={preview} />
    </StyledContainerNarrow>
  );
}

const ErrorPage = ({ error }) => {
  return (
    <CenterGrid>
      <div>
        <p>Could not load preview 😞</p>
        <ErrorLook style={{ fontSize: '1rem' }}>{error.message}</ErrorLook>
      </div>
    </CenterGrid>
  );
};

const CenterGrid = styled.div`
  display: grid;
  height: min(80vh, 1000px);
  width: 100%;
  place-items: center;
  font-size: calc(clamp(1rem, 5vw, 2.4rem) + 0.1rem);
`;

const StyledContainerNarrow = styled(ContainerNarrow)`
  max-width: 85ch;
`;
