import { Button } from '@components/Button';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import { ContainerNarrow } from '@components/Containers';
import Markdown from '@components/datatypes/Markdown';
import { JSONEditor } from '@components/JSONEditor';
import { Column, Row } from '@components/Row';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import {
  core,
  server,
  useCanWrite,
  useString,
  useValue,
  type Server,
} from '@tomic/react';
import { useCreatePlugin } from '@views/Plugin/createPlugin';
import type { ResourcePageProps } from '@views/ResourcePage';
import type { JSONSchema7 } from 'ai';
import { constructOpenURL } from '@helpers/navigation';
import { lazy, useId, useState } from 'react';
import { FaFloppyDisk, FaGear, FaTrash } from 'react-icons/fa6';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { ConfigReference } from './ConfigReference';
import { AssignRights } from './AssignRights';
import { PluginPermissions } from './PluginPermissions';
import { hasPermission, isPluginPermissions } from './pluginUtils';

const UpdatePluginButton = lazy(
  () => import('@chunks/Plugins/UpdatePluginButton'),
);

export const PluginPage: React.FC<ResourcePageProps<Server.Plugin>> = ({
  resource,
}) => {
  const configLabelId = useId();
  const canWrite = useCanWrite(resource);
  const navigate = useNavigateWithTransition();
  const [showUninstallDialog, setShowUninstallDialog] = useState(false);
  const [name] = useString(resource, core.properties.name);
  const [namespace] = useString(resource, server.properties.namespace);
  const [config, setConfig] = useValue(resource, server.properties.config);
  const [permissions] = useValue(resource, server.properties.pluginPermissions);
  const [configValid, setConfigValid] = useState(true);
  const title = `${namespace ? `${namespace}/` : ''}${name}`;
  const parent = resource.props.parent;

  const { uninstallPlugin } = useCreatePlugin();

  const hasFullDriveAccess = hasPermission(permissions, 'full-drive-access');

  return (
    <ContainerNarrow>
      <Column gap='2rem'>
        <div>
          <Row justify='space-between'>
            <PluginName>{title}</PluginName>
            <span>v{resource.props.version}</span>
          </Row>
          <PluginAuthor>by {resource.props.pluginAuthor}</PluginAuthor>
        </div>
        <Column>
          {canWrite && (
            <Row justify='flex-end'>
              <UpdatePluginButton plugin={resource} />
              <Button alert onClick={() => setShowUninstallDialog(true)}>
                <FaTrash />
                <span>Uninstall</span>
              </Button>
            </Row>
          )}
          {resource.props.description && (
            <DescriptionWrapper aria-label='Plugin Description'>
              <Markdown text={resource.props.description!} />
            </DescriptionWrapper>
          )}
        </Column>
        {canWrite && (
          <AssignRights plugin={resource} disabled={hasFullDriveAccess} />
        )}
        {/* Secrets are declared by name in a plugin's source; a WASM plugin's
            manifest carries origins but no names, so it has nothing to render
            slots from yet. The endpoint still serves it. */}
        <Column>
          <Row center justify='space-between'>
            <h3 id={configLabelId}>
              <Row gap='0.5ch' center>
                <FaGear />
                <span>Config</span>
              </Row>
            </h3>
            <Button
              disabled={!configValid || !resource.hasUnsavedChanges()}
              onClick={() => resource.save()}
            >
              <FaFloppyDisk />
              <span>Save</span>
            </Button>
          </Row>
          <JSONEditor
            labelId={configLabelId}
            initialValue={JSON.stringify(config, null, 2)}
            onChange={v => {
              try {
                setConfig(JSON.parse(v));
              } catch (e) {
                // Do nothing
              }
            }}
            schema={resource.props.jsonSchema as JSONSchema7}
            showErrorStyling={!configValid}
            onValidationChange={setConfigValid}
          />
        </Column>
        {resource.props.jsonSchema && (
          <ConfigReference schema={resource.props.jsonSchema as JSONSchema7} />
        )}
        {isPluginPermissions(permissions) && (
          <PluginPermissions permissions={permissions} />
        )}
      </Column>
      <ConfirmationDialog
        title='Uninstall Plugin'
        show={showUninstallDialog}
        theme={ConfirmationDialogTheme.Alert}
        confirmLabel='Uninstall'
        bindShow={setShowUninstallDialog}
        onConfirm={async () => {
          await uninstallPlugin(resource);
          navigate(constructOpenURL(parent));
          toast.success('Plugin uninstalled');
        }}
        onCancel={() => setShowUninstallDialog(false)}
      >
        Are you sure you want to uninstall this plugin?
      </ConfirmationDialog>
    </ContainerNarrow>
  );
};

const PluginName = styled.span`
  font-weight: bold;
  font-size: 1.2rem;
`;

const DescriptionWrapper = styled.section`
  background-color: ${p => p.theme.colors.bg1};
  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};
  max-height: 33rem;
  overflow-y: auto;
`;

const PluginAuthor = styled.span`
  color: ${p => p.theme.colors.textLight};
`;
