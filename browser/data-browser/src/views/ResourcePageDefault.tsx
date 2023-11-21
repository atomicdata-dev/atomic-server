import { useString, properties } from '@tomic/react';
import AllProps from '../components/AllProps';
import { ClassDetail } from '../components/ClassDetail';
import { ContainerNarrow } from '../components/Containers';
import { ValueForm } from '../components/forms/ValueForm';
import { ResourcePageProps } from './ResourcePage';
import { CommitDetail } from '../components/CommitDetail';
import { Details } from '../components/Detail';
import { EditableTitle } from '../components/EditableTitle';

/**
 * The properties that are shown in an alternative, custom way in default views.
 * If you use this, make sure you check the list every once in a while to make
 * sure you're not missing something important.
 */
export const defaultHiddenProps = [
  // Shown as title
  properties.name,
  properties.shortname,
  properties.file.filename,
  // Shown separately
  properties.description,
  // Content should indicate Class in custom views (e.g. document looks like a document)
  properties.isA,
  // Shown in navigation
  properties.parent,
  // Shown in rights / share menu
  properties.write,
  properties.read,
  // Shown in CommitDetail
  properties.commit.lastCommit,
];

/**
 * The Resource view that is used when no specific one fits better. It lists all
 * properties.
 */
export function ResourcePageDefault({
  resource,
}: ResourcePageProps): JSX.Element {
  const [lastCommit] = useString(resource, properties.commit.lastCommit);

  return (
    <ContainerNarrow>
      <EditableTitle resource={resource} />
      <Details>
        <ClassDetail resource={resource} />
        <CommitDetail commitSubject={lastCommit} />
      </Details>
      <ValueForm resource={resource} propertyURL={properties.description} />
      <AllProps
        resource={resource}
        except={defaultHiddenProps}
        editable
        columns
      />
    </ContainerNarrow>
  );
}
