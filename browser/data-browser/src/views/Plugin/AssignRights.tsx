import { Button } from '@components/Button';
import { Dialog, useDialog } from '@components/Dialog';
import { ParentPicker } from '@components/ParentPicker/ParentPicker';
import {
  commits,
  core,
  dataBrowser,
  server,
  useCollection,
  useStore,
  type Resource,
  type Server,
} from '@tomic/react';
import { useState } from 'react';
import { PermissionRow } from './PermissionRow';
import { TableList } from '@components/TableList';
import { Column, Row } from '@components/Row';
import { FaPlus, FaShield } from 'react-icons/fa6';
import { DashedButton } from '@views/OntologyPage/DashedButton';
import { styled } from 'styled-components';

interface AssignRightsProps {
  plugin: Resource<Server.Plugin>;
  disabled?: boolean;
}

const shouldRender = (resource: Resource) => {
  return [
    commits.classes.commit,
    dataBrowser.classes.tag,
    server.classes.plugin,
  ].every(c => !resource.hasClasses(c));
};

export const AssignRights: React.FC<AssignRightsProps> = ({
  plugin,
  disabled,
}) => {
  const store = useStore();
  const [selectedResource, setSelectedResource] = useState<string>();

  const pluginAgent = plugin.props.pluginAgent;

  const { invalidateCollection, mapAll } = useCollection({
    property: core.properties.read,
    value: pluginAgent,
  });

  const addResource = async () => {
    try {
      if (!pluginAgent || !selectedResource) return;

      const pickedResource = await store.getResource(selectedResource);
      pickedResource.push(core.properties.read, [pluginAgent], true);
      await pickedResource.save();
      invalidateCollection();
    } catch (e) {
      console.error(e);
    } finally {
      setSelectedResource(undefined);
    }
  };

  const [dialogProps, show, close, isOpen] = useDialog({
    onSuccess: addResource,
  });

  if (!pluginAgent) return null;

  return (
    <Column>
      <h3>
        <Row gap='0.5ch'>
          <FaShield />
          <span>Assign Rights</span>
        </Row>
      </h3>
      <StyledTableList disabled={disabled}>
        <thead>
          <tr>
            <ResourceHeading>Resource</ResourceHeading>
            <th>Read</th>
            <th>Write</th>
          </tr>
        </thead>
        <tbody>
          {mapAll(({ collection, index }) => (
            <PermissionRow
              key={index}
              collection={collection}
              index={index}
              pluginAgent={plugin.props.pluginAgent ?? ''}
              onReadUpdate={invalidateCollection}
            />
          ))}
          <tr>
            <td>
              <DashedButton onClick={show} buttonHeight='2rem'>
                <FaPlus />
              </DashedButton>
            </td>
          </tr>
        </tbody>
      </StyledTableList>
      <Dialog {...dialogProps}>
        {isOpen && (
          <>
            <Dialog.Title>
              <h1>Pick a resource</h1>
            </Dialog.Title>
            <Dialog.Content>
              <ParentPicker
                value={selectedResource}
                onChange={s => {
                  setSelectedResource(s);
                }}
                shouldBeRendered={shouldRender}
              />
            </Dialog.Content>
            <Dialog.Actions>
              <Button subtle onClick={() => close(false)}>
                Cancel
              </Button>
              <Button onClick={() => close(true)}>Assign</Button>
            </Dialog.Actions>
          </>
        )}
      </Dialog>
    </Column>
  );
};

const ResourceHeading = styled.th`
  text-align: start;
`;

const StyledTableList = styled(TableList)<{ disabled?: boolean }>`
  opacity: ${p => (p.disabled ? 0.5 : 1)};
  pointer-events: ${p => (p.disabled ? 'none' : 'auto')};

  & th {
    font-weight: normal;
  }
  & th:nth-child(2),
  & th:nth-child(3),
  & td:nth-child(2),
  & td:nth-child(3) {
    width: 4rem;
    text-align: center;
  }
`;
