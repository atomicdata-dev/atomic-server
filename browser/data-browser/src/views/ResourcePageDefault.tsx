import {
  useString,
  core,
  server,
  commits,
  useCanWrite,
  dataBrowser,
} from '@tomic/react';
import AllProps from '../components/AllProps';
import { ClassDetail } from '../components/ClassDetail';
import { ContainerNarrow } from '../components/Containers';
import { ValueForm } from '../components/forms/ValueForm/ValueForm';
import { ResourcePageProps } from './ResourcePage';
import { CommitDetail } from '../components/CommitDetail';
import { Details } from '../components/Detail';
import { EditableTitle } from '../components/EditableTitle';
import { FaPencil } from 'react-icons/fa6';
import {
  IconButton,
  IconButtonVariant,
} from '../components/IconButton/IconButton';
import { Column, Row } from '../components/Row';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { editURL } from '../helpers/navigation';

/**
 * The properties that are shown in an alternative, custom way in default views.
 * If you use this, make sure you check the list every once in a while to make
 * sure you're not missing something important.
 */
export const defaultHiddenProps = [
  // Shown as title
  core.properties.name,
  core.properties.shortname,
  server.properties.filename,
  // Shown separately
  core.properties.description,
  // Content should indicate Class in custom views (e.g. document looks like a document)
  core.properties.isA,
  // Shown in navigation
  core.properties.parent,
  // Shown in rights / share menu
  core.properties.write,
  core.properties.read,
  // Shown in CommitDetail
  commits.properties.lastCommit,
  dataBrowser.properties.subResources,
];

/**
 * The Resource view that is used when no specific one fits better. It lists most
 * properties.
 */
export function ResourcePageDefault({
  resource,
}: ResourcePageProps): JSX.Element {
  const [lastCommit] = useString(resource, commits.properties.lastCommit);
  const [canEdit] = useCanWrite(resource);
  const navigate = useNavigateWithTransition();

  return (
    <ContainerNarrow>
      <Column>
        <Row justify='space-between'>
          <EditableTitle resource={resource} />
          {canEdit && (
            <IconButton
              title='Edit'
              variant={IconButtonVariant.Square}
              onClick={() => navigate(editURL(resource.subject))}
            >
              <FaPencil />
            </IconButton>
          )}
        </Row>
        <Details>
          <ClassDetail resource={resource} />
          <CommitDetail commitSubject={lastCommit} />
        </Details>
        <ValueForm
          resource={resource}
          propertyURL={core.properties.description}
        />
        <AllProps
          resource={resource}
          except={defaultHiddenProps}
          editable
          columns
        />
      </Column>
    </ContainerNarrow>
  );
}
