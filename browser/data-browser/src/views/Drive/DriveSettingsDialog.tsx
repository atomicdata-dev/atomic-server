import {
  Datatype,
  dataBrowser,
  server,
  useArray,
  useCanWrite,
  useProperty,
  type Resource,
  type Server,
} from '@tomic/react';
import { lazy, Suspense, type JSX } from 'react';
import { FaXmark } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Dialog } from '@components/Dialog';
import type { InternalDialogProps } from '@components/Dialog';
import { Column, Row } from '@components/Row';
import InputSwitcher from '@components/forms/InputSwitcher';
import { SettingsGroup, SettingsSection } from '@components/Settings';
import { Tag } from '@components/Tag/Tag';
import { CreateTagRow } from '@components/Tag/CreateTagRow';
import { ValueFormAddButton } from '@components/forms/ValueForm/ValueFormAddButton';
import { constructOpenURL } from '@helpers/navigation';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { PluginList } from './PluginList';

const NewPluginButton = lazy(() => import('@chunks/Plugins/NewPluginButton'));

interface DriveSettingsDialogProps {
  drive: Resource<Server.Drive>;
  dialogProps: InternalDialogProps;
  isOpen: boolean;
}

/** The drive's configuration: kept out of the page so it can be a home. */
export function DriveSettingsDialog({
  drive,
  dialogProps,
  isOpen,
}: DriveSettingsDialogProps): JSX.Element {
  return (
    <Dialog {...dialogProps} width='44rem'>
      <Dialog.Title>
        <h1>Drive settings</h1>
      </Dialog.Title>
      <Dialog.Content>
        {isOpen && <DriveSettingsBody drive={drive} />}
      </Dialog.Content>
    </Dialog>
  );
}

function DriveSettingsBody({
  drive,
}: {
  drive: Resource<Server.Drive>;
}): JSX.Element {
  const defaultOntologyProp = useProperty(server.properties.defaultOntology);
  const canEdit = useCanWrite(drive);

  return (
    <SettingsGroup>
      <SettingsSection label='Tags' initialState>
        <DriveTagList resource={drive} />
      </SettingsSection>
      <SettingsSection label='LLM Instructions' initialState>
        <p>
          A short description given to the AI Agent, use this to tell it what
          this drive is about, link important resources etc.
        </p>
        <ValueFormAddButton
          resource={drive}
          propertyURL={server.properties.llmTxt}
          datatype={Datatype.MARKDOWN}
          buttonLabel='Add LLM instructions'
        />
      </SettingsSection>
      <SettingsSection label='Default Ontology' initialState>
        <InputSwitcher
          commit
          resource={drive}
          property={defaultOntologyProp}
          disabled={!canEdit}
        />
      </SettingsSection>
      <SettingsSection label='Plugins' initialState>
        <Column gap='1rem'>
          <PluginList drive={drive} />
          {canEdit && (
            <Suspense fallback={null}>
              <NewPluginButton drive={drive} />
            </Suspense>
          )}
        </Column>
      </SettingsSection>
    </SettingsGroup>
  );
}

function DriveTagList({ resource }: { resource: Resource }) {
  const canEdit = useCanWrite(resource);
  const navigate = useNavigateWithTransition();
  const [tags, setTags, pushTags] = useArray(
    resource,
    dataBrowser.properties.tagList,
    {
      commit: true,
    },
  );

  const handleDelete = (subject: string) => {
    setTags(tags.filter(t => t !== subject));
  };

  const handleNewTag = async (tag: Resource) => {
    await tag.save();
    pushTags([tag.subject]);
  };

  const handleTagClick =
    (subject: string): React.MouseEventHandler<HTMLAnchorElement> =>
    e => {
      e.preventDefault();
      navigate(constructOpenURL(subject));
    };

  if (tags.length === 0 && !canEdit) {
    return null;
  }

  return (
    <Column gap='0.75rem'>
      <Row gap='0.5rem' wrapItems>
        {tags.map(tag => (
          <TagItem key={tag}>
            <TagLink href={constructOpenURL(tag)} onClick={handleTagClick(tag)}>
              <Tag subject={tag} />
            </TagLink>
            {canEdit && (
              <DeleteTagButton
                type='button'
                title='Remove tag'
                onClick={() => handleDelete(tag)}
              >
                <FaXmark />
              </DeleteTagButton>
            )}
          </TagItem>
        ))}
      </Row>
      {canEdit && (
        <CreateTagRow parent={resource.subject} onNewTag={handleNewTag} />
      )}
    </Column>
  );
}

const TagItem = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.25ch;
`;

const TagLink = styled.a`
  text-decoration: none;
  display: contents;
`;

const DeleteTagButton = styled.button`
  display: inline-flex;
  align-items: center;
  padding: 0.2em;
  border: none;
  background: transparent;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
  border-radius: ${p => p.theme.radius};
  opacity: 0;
  font-size: 0.75em;

  ${TagItem}:hover & {
    opacity: 1;
  }

  &:hover {
    color: ${p => p.theme.colors.alert};
  }

  @media (hover: none) {
    opacity: 1;
  }
`;
