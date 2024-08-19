import { styled, css } from 'styled-components';
import {
  useResource,
  useString,
  useTitle,
  Resource,
  core,
  server,
} from '@tomic/react';
import { constructOpenURL } from '../helpers/navigation';
import { Row } from './Row';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { useSettings } from '../helpers/AppSettings';
import { Button } from './Button';
import { BREADCRUMB_BAR_TRANSITION_TAG } from '../helpers/transitionName';
import ResourceContextMenu from './ResourceContextMenu';
import { MenuBarDropdownTrigger } from './ResourceContextMenu/MenuBarDropdownTrigger';

type ParentProps = {
  resource: Resource;
};

/** Breadcrumb list. Recursively renders parents. */
function Parent({ resource }: ParentProps): JSX.Element {
  const [parent] = useString(resource, core.properties.parent);

  return (
    <ParentWrapper aria-label='Breadcrumbs'>
      <Row fullWidth center gap='initial'>
        {parent ? (
          <NestedParent subject={parent} depth={0} />
        ) : (
          <DriveMismatch subject={resource.subject} />
        )}
        <BreadCrumbCurrent>{resource.title}</BreadCrumbCurrent>
        <Spacer />
        <ButtonArea>
          <ResourceContextMenu
            isMainMenu
            subject={resource.subject}
            trigger={MenuBarDropdownTrigger}
          />
        </ButtonArea>
      </Row>
    </ParentWrapper>
  );
}

const ParentWrapper = styled.nav`
  height: ${p => p.theme.heights.breadCrumbBar};
  padding-inline: ${p => p.theme.size(2)};
  border-bottom: 1px solid ${props => props.theme.colors.bg2};
  background-color: ${props => props.theme.colors.bg};
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: flex-start;

  view-transition-name: ${BREADCRUMB_BAR_TRANSITION_TAG};
`;

type NestedParentProps = {
  subject: string;
  depth: number;
};

const MAX_BREADCRUMB_DEPTH = 4;

/** Shows a "Set drive" button if the current drive is different from the Subject */
function DriveMismatch({ subject }: { subject: string }) {
  const { drive, setDrive } = useSettings();
  const resource = useResource(subject, { allowIncomplete: true });
  const [title] = useTitle(resource);
  const classes = resource.getClasses();

  const handleSetDrive = () => {
    setDrive(subject);
  };

  const mismatch = subject && subject !== drive;

  if (mismatch && classes[0] === server.classes.drive) {
    return (
      <Button
        title={`Set ${title} as current drive`}
        subtle
        onClick={handleSetDrive}
      >
        Set Drive
      </Button>
    );
  }

  return null;
}

/** The actually recursive part */
function NestedParent({ subject, depth }: NestedParentProps): JSX.Element {
  const resource = useResource(subject, { allowIncomplete: true });
  const [parent] = useString(resource, core.properties.parent);
  const navigate = useNavigateWithTransition();
  const [title] = useTitle(resource);

  // Prevent infinite recursion, set a limit to parent breadcrumbs
  if (depth > MAX_BREADCRUMB_DEPTH) {
    return <Breadcrumb>Set as drive</Breadcrumb>;
  }

  const handleClick: React.MouseEventHandler<HTMLAnchorElement> = e => {
    e.preventDefault();
    navigate(constructOpenURL(subject));
  };

  return (
    <>
      {parent ? (
        <NestedParent subject={parent} depth={depth + 1} />
      ) : (
        <DriveMismatch subject={subject} />
      )}
      <Breadcrumb href={subject} onClick={handleClick}>
        {title}
      </Breadcrumb>
      <Divider>{'/'}</Divider>
    </>
  );
}

const Divider = styled.div`
  padding: 0.1rem 0.2rem;
`;

const BreadCrumbBase = css`
  font-size: ${props => props.theme.fontSizeBody}rem;
  font-family: ${props => props.theme.fontFamily};
  padding: 0.1rem 0.5rem;
  color: ${p => p.theme.colors.textLight};
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const BreadCrumbCurrent = styled.span`
  ${BreadCrumbBase}
`;

const Breadcrumb = styled.a`
  ${BreadCrumbBase}
  align-self: center;
  cursor: 'pointer';
  text-decoration: none;
  border-radius: ${p => p.theme.radius};

  &:hover {
    background: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }

  &:active {
    background: ${p => p.theme.colors.bg2};
  }
`;

const Spacer = styled.span`
  flex: 1;
`;

const ButtonArea = styled.div`
  justify-self: flex-end;
  color: ${p => p.theme.colors.textLight};
`;

export default Parent;
