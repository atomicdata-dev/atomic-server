import {
  classes,
  properties,
  useArray,
  useCanWrite,
  useResources,
  useString,
} from '@tomic/react';
import React, { useMemo } from 'react';
import { styled } from 'styled-components';
import { EditableTitle } from '../../components/EditableTitle';
import { FileDropZone } from '../../components/forms/FileDropzone/FileDropzone';
import { useNewRoute } from '../../helpers/useNewRoute';
import { ResourcePageProps } from '../ResourcePage';
import { DisplayStyleButton } from './DisplayStyleButton';
import { GridView } from './GridView';
import { ListView } from './ListView';

const displayStyleOpts = {
  commit: true,
};

const viewMap = new Map([
  [classes.displayStyles.list, ListView],
  [classes.displayStyles.grid, GridView],
]);

const subResourceOpts = {
  commit: true,
};

export function FolderPage({ resource }: ResourcePageProps) {
  const [subResourceSubjects] = useArray(
    resource,
    properties.subResources,
    subResourceOpts,
  );
  const [displayStyle, setDisplayStyle] = useString(
    resource,
    properties.displayStyle,
    displayStyleOpts,
  );

  const View = useMemo(
    () => viewMap.get(displayStyle!) ?? ListView,
    [displayStyle],
  );

  const subResources = useResources(subResourceSubjects);
  const navigateToNewRoute = useNewRoute(resource.getSubject());
  const [canEdit] = useCanWrite(resource);

  return (
    <FullPageWrapper view={displayStyle!}>
      <TitleBar>
        <TitleBarInner>
          <EditableTitle resource={resource} />
          <DisplayStyleButton
            onClick={setDisplayStyle}
            displayStyle={displayStyle}
          />
        </TitleBarInner>
      </TitleBar>
      <Wrapper>
        <FileDropZone parentResource={resource}>
          <View
            subResources={subResources}
            onNewClick={navigateToNewRoute}
            showNewButton={canEdit!}
          />
        </FileDropZone>
      </Wrapper>
    </FullPageWrapper>
  );
}

const TitleBar = styled.div`
  padding: ${p => p.theme.margin}rem;
`;

const TitleBarInner = styled.div`
  display: flex;
  width: var(--container-width);
  margin-inline: auto;
  justify-content: space-between;
`;

const Wrapper = styled.div`
  width: 100%;
  padding: ${p => p.theme.margin}rem;
  flex: 1;
`;

interface FullPageWrapperProps {
  view: string;
}

const FullPageWrapper = styled.div<FullPageWrapperProps>`
  --container-width: min(1300px, 100%);
  min-height: ${p => p.theme.heights.fullPage};
  padding-bottom: ${p => p.theme.heights.floatingSearchBarPadding};
  display: flex;
  flex-direction: column;
`;
