import { styled, css } from 'styled-components';
import { useResource, useString, useTitle, Resource, core } from '@tomic/react';
import { constructOpenURL } from '../helpers/navigation';
import { FaSearch } from 'react-icons/fa';
import { Row } from './Row';
import { useQueryScopeHandler } from '../hooks/useQueryScope';
import { IconButton } from './IconButton/IconButton';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { useSettings } from '../helpers/AppSettings';
import { Button } from './Button';

type ParentProps = {
  resource: Resource;
};

export const PARENT_PADDING_BLOCK = '0.2rem';

/** Breadcrumb list. Recursively renders parents. */
function Parent({ resource }: ParentProps): JSX.Element {
  const [parent] = useString(resource, core.properties.parent);
  const { enableScope } = useQueryScopeHandler(resource.getSubject());

  return (
    <ParentWrapper aria-label='Breadcrumbs'>
      <Row fullWidth center gap='initial'>
        {parent ? (
          <NestedParent subject={parent} depth={0} />
        ) : (
          <DriveMismatch subject={resource.getSubject()} />
        )}
        <BreadCrumbCurrent>{resource.title}</BreadCrumbCurrent>
        <Spacer />
        <ScopedSearchButton
          onClick={enableScope}
          title={`Search in ${resource.title}`}
          color='textLight'
        >
          <FaSearch />
        </ScopedSearchButton>
      </Row>
    </ParentWrapper>
  );
}

const ParentWrapper = styled.nav`
  height: ${p => p.theme.heights.breadCrumbBar};
  padding-block: ${PARENT_PADDING_BLOCK};
  padding-inline: 0.5rem;
  color: ${props => props.theme.colors.textLight2};
  border-bottom: 1px solid ${props => props.theme.colors.bg2};
  background-color: ${props => props.theme.colors.bg};
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: flex-start;

  view-transition-name: breadcrumb-bar;
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

  const handleSetDrive = () => {
    setDrive(subject);
  };

  const mismatch = subject && subject !== drive;

  if (mismatch) {
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

  function handleClick(e) {
    e.preventDefault();
    navigate(constructOpenURL(subject));
  }

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

const ScopedSearchButton = styled(IconButton)`
  justify-self: flex-end;
`;

export default Parent;
