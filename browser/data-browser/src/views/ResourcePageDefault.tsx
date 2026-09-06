import {
  useCreatedBy,
  useCreatedAt,
  useCanWrite,
  dataBrowser,
  core,
  server,
  commits,
} from '@tomic/react';
import { styled } from 'styled-components';
import AllProps from '../components/AllProps';
import { ClassDetail } from '../components/ClassDetail';
import { ContainerNarrow } from '../components/Containers';
import { ValueForm } from '../components/forms/ValueForm/ValueForm';
import { ResourcePageProps } from './ResourcePage';
import { CommitDetail } from '../components/CommitDetail';
import { Details } from '../components/Detail';
import { EditableTitle } from '../components/EditableTitle';
import { ResourceCoverImage } from '../components/ResourceDecorations';
import { FaPencil } from 'react-icons/fa6';
import { Button } from '../components/Button';
import { Column, Row } from '../components/Row';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { editURL } from '../helpers/navigation';

import type { JSX } from 'react';

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
  dataBrowser.properties.tags,
  // Shown as page decorations (icon + cover banner)
  dataBrowser.properties.emoji,
  dataBrowser.properties.coverImage,
];

/**
 * The Resource view that is used when no specific one fits better. It lists most
 * properties.
 */
export function ResourcePageDefault({
  resource,
}: ResourcePageProps): JSX.Element {
  const createdBy = useCreatedBy(resource);
  const createdAt = useCreatedAt(resource);
  const canEdit = useCanWrite(resource);
  const navigate = useNavigateWithTransition();

  return (
    <>
      <ResourceCoverImage resource={resource} />
      <ContainerNarrow>
        <Column>
          <Row justify='space-between' align='flex-start'>
            <EditableTitle resource={resource} withDecorations />
            {canEdit && (
              <EditButton
                ghost
                onClick={() => navigate(editURL(resource.subject))}
              >
                <FaPencil aria-hidden /> Edit
              </EditButton>
            )}
          </Row>
          <CompactDetails>
            <ClassDetail resource={resource} />
            <CommitDetail createdAt={createdAt} createdBy={createdBy} short />
          </CompactDetails>
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
    </>
  );
}

/** Never let a long/wrapped title squash the Edit button down to nothing. */
const EditButton = styled(Button)`
  flex-shrink: 0;
`;

/** `Details`' shared `space-between` reads badly with only 2 children once
 *  they wrap on narrow screens (big uneven gaps) — this page wants a
 *  compact, left-aligned row instead. Local override: `Details` is also
 *  used by MessageCard/MessagePage, where space-between is intentional. */
const CompactDetails = styled(Details)`
  justify-content: flex-start;
  gap: ${p => p.theme.size(4)};
`;
