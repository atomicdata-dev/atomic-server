import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useResource, useStore, Version } from '@tomic/react';

import { ContainerNarrow } from '../../components/Containers';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { ErrorLook } from '../../components/ErrorLook';
import styled from 'styled-components';
import { useVersions } from './useVersions';
import { groupVersionsByMonth, setResourceToVersion } from './versionHelpers';
import { toast } from 'react-hot-toast';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../helpers/navigation';
import { HistoryDesktopView } from './HistoryDesktopView';
import { HistoryMobileView } from './HistoryMobileView';
import { useMediaQuery } from '../../hooks/useMediaQuery';

/** Shows an activity log of previous versions */
export function History(): JSX.Element {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const isSmallScreen = useMediaQuery('(max-width: 500px)');
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  const { versions, loading, error } = useVersions(resource);
  const [selectedVersion, setSelectedVersion] = useState<Version | undefined>();

  const groupedVersions: {
    [key: string]: Version[];
  } = useMemo(() => groupVersionsByMonth(versions), [versions]);

  useEffect(() => {
    if (versions.length > 0) {
      setSelectedVersion(versions[versions.length - 1]);
    }
  }, [versions]);

  const setResourceToCurrentVersion = async () => {
    if (selectedVersion && subject) {
      await setResourceToVersion(resource, selectedVersion, store);
      toast.success('Resource version updated');
      navigate(constructOpenURL(subject));
    }
  };

  const nextVersion = useCallback(() => {
    const currentIndex = versions.findIndex(v => v === selectedVersion);

    if (currentIndex === -1 || currentIndex === versions.length - 1) {
      return;
    }

    setSelectedVersion(versions[currentIndex + 1]);
  }, [versions, selectedVersion]);

  const previousVersion = useCallback(() => {
    const currentIndex = versions.findIndex(v => v === selectedVersion);

    if (currentIndex === -1 || currentIndex === 0) {
      return;
    }

    setSelectedVersion(versions[currentIndex - 1]);
  }, [versions, selectedVersion]);

  const ViewComp = isSmallScreen ? HistoryMobileView : HistoryDesktopView;

  const isCurrentVersion = selectedVersion === versions[versions.length - 1];

  if (loading) {
    return <ContainerNarrow>Loading history of {subject}...</ContainerNarrow>;
  }

  if (error) {
    return (
      <ContainerNarrow>
        <ErrorLook>{error.message}</ErrorLook>
      </ContainerNarrow>
    );
  }

  return (
    <SplitView about={subject}>
      <ViewComp
        resource={resource}
        groupedVersions={groupedVersions}
        selectedVersion={selectedVersion}
        isCurrentVersion={isCurrentVersion}
        onNextVersion={nextVersion}
        onPreviousVersion={previousVersion}
        onSelectVersion={setSelectedVersion}
        onVersionAccept={setResourceToCurrentVersion}
      />
    </SplitView>
  );
}

const SplitView = styled.main`
  display: flex;
  /* Fills entire view on all devices */
  width: 100%;
  height: 100%;
  height: calc(100vh - 6rem);
  padding: ${p => p.theme.margin}rem;
  gap: ${p => p.theme.margin}rem;

  /* Fix code blocks not shrinking causing page overflow. */
  & code {
    word-break: break-word;
  }
`;
