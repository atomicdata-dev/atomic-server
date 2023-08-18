import {
  urls,
  useArray,
  useCanWrite,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import React, { useEffect, useState } from 'react';
import { FaPlus } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';
import { styled } from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';
import { constructOpenURL } from '../../helpers/navigation';
import { paths } from '../../routes/paths';
import { Button } from '../Button';
import { ResourceSideBar } from './ResourceSideBar/ResourceSideBar';
import { SideBarHeader } from './SideBarHeader';
import { shortcuts } from '../HotKeyWrapper';
import { ErrorLook } from '../ErrorLook';
import { DriveSwitcher } from './DriveSwitcher';
import { IconButton } from '../IconButton/IconButton';
import { Row } from '../Row';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { ScrollArea } from '../ScrollArea';

interface SideBarDriveProps {
  /** Closes the sidebar on small screen devices */
  handleClickItem: () => unknown;
}

/** Shows the current Drive, it's children and an option to change to a different Drive */
export function SideBarDrive({
  handleClickItem,
}: SideBarDriveProps): JSX.Element {
  const store = useStore();
  const { drive, agent } = useSettings();
  const driveResource = useResource(drive);
  const [subResources] = useArray(driveResource, urls.properties.subResources);
  const [title] = useTitle(driveResource);
  const navigate = useNavigate();
  const [agentCanWrite] = useCanWrite(driveResource);
  const [currentSubject] = useCurrentSubject();
  const currentResource = useResource(currentSubject);
  const [ancestry, setAncestry] = useState<string[]>([]);

  useEffect(() => {
    store.getResourceAncestry(currentResource).then(result => {
      setAncestry(result);
    });
  }, [store, currentResource]);

  return (
    <>
      <SideBarHeader>
        <TitleButton
          clean
          title={`Your current baseURL is ${drive}`}
          data-test='sidebar-drive-open'
          onClick={() => {
            handleClickItem();
            navigate(constructOpenURL(drive));
          }}
        >
          <DriveTitle data-test='current-drive-title'>
            {title || drive}{' '}
          </DriveTitle>
        </TitleButton>
        <HeadingButtonWrapper gap='0'>
          {agentCanWrite && (
            <IconButton
              onClick={() => navigate(paths.new)}
              title={`Create a new resource in this drive (${shortcuts.new})`}
              data-test='sidebar-new-resource'
            >
              <FaPlus />
            </IconButton>
          )}
          <DriveSwitcher />
        </HeadingButtonWrapper>
      </SideBarHeader>
      <StyledScrollArea>
        <ListWrapper>
          {driveResource.isReady() ? (
            subResources.map(child => {
              return (
                <ResourceSideBar
                  key={child}
                  subject={child}
                  ancestry={ancestry}
                  onClick={handleClickItem}
                />
              );
            })
          ) : driveResource.loading ? null : (
            <SideBarErr>
              {driveResource.error &&
                (driveResource.isUnauthorized()
                  ? agent
                    ? 'unauthorized'
                    : driveResource.error.message
                  : driveResource.error.message)}
            </SideBarErr>
          )}
        </ListWrapper>
      </StyledScrollArea>
    </>
  );
}

const DriveTitle = styled.h2`
  margin: 0;
  padding: 0;
  font-size: 1.4rem;
  flex: 1;
`;

const TitleButton = styled(Button)`
  text-align: left;
  flex: 1;
`;

const SideBarErr = styled(ErrorLook)`
  padding-left: ${props => props.theme.margin}rem;
`;

const ListWrapper = styled.div`
  overflow-x: hidden;
  margin-left: 0.5rem;
`;

const HeadingButtonWrapper = styled(Row)`
  color: ${p => p.theme.colors.main};
  font-size: 0.9rem;
`;

const StyledScrollArea = styled(ScrollArea)`
  overflow: hidden;
`;
