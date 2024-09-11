import {
  classes,
  useCanWrite,
  useResources,
  type DataBrowser,
} from '@tomic/react';
import { useMemo } from 'react';
import { styled } from 'styled-components';
import { EditableTitle } from '../../components/EditableTitle';
import { FileDropZone } from '../../components/forms/FileDropzone/FileDropzone';
import { useNewRoute } from '../../helpers/useNewRoute';
import { ResourcePageProps } from '../ResourcePage';
import { DisplayStyleButton } from './DisplayStyleButton';
import { GridView } from './GridView';
import { ListView } from './ListView';
import { useLocalStorage } from '../../hooks/useLocalStorage';

type PreferredFolderStyles = Record<string, string>;

const viewMap = new Map([
  [classes.displayStyles.list, ListView],
  [classes.displayStyles.grid, GridView],
]);

const displayStyleStorageKey = 'folderDisplayPrefs';

const useDisplayStyle = (
  subject: string,
): [
  preferredStyle: string | undefined,
  setPreferredStyle: (style: string) => void,
] => {
  const [preferredStyles, setPreferredStyles] =
    useLocalStorage<PreferredFolderStyles>(displayStyleStorageKey, {});

  const setPreferredStyle = (style: string) => {
    setPreferredStyles({ ...preferredStyles, [subject]: style });
  };

  return [preferredStyles[subject], setPreferredStyle];
};

export function FolderPage({
  resource,
}: ResourcePageProps<DataBrowser.Folder>) {
  const [preferedDisplayStyle, setPreferedDisplayStyle] = useDisplayStyle(
    resource.subject,
  );

  const displayStyle = preferedDisplayStyle ?? resource.props.displayStyle;

  const View = useMemo(
    () => viewMap.get(displayStyle!) ?? ListView,
    [displayStyle],
  );

  const subResources = useResources(resource.props.subResources);
  const navigateToNewRoute = useNewRoute(resource.subject);
  const [canEdit] = useCanWrite(resource);

  return (
    <FullPageWrapper view={displayStyle!}>
      <TitleBar>
        <TitleBarInner>
          <EditableTitle resource={resource} />
          <DisplayStyleButton
            onClick={setPreferedDisplayStyle}
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
