import { Button } from '@components/Button';
import { Dialog, useDialog } from '@components/Dialog';
import type { JSONValue, Resource, Server } from '@tomic/react';
import { useId, useRef, useState } from 'react';
import { FaPlus } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Column, Row } from '@components/Row';
import { JSONEditor } from '@components/JSONEditor';
import Markdown from '@components/datatypes/Markdown';
import { useCreatePlugin } from '@views/Plugin/createPlugin';
import { readZip, type PluginMetadata } from './plugins';
import { ConfigReference } from '@views/Plugin/ConfigReference';
import { PluginPermissions } from '@views/Plugin/PluginPermissions';
import toast from 'react-hot-toast';
import { useCustomViews } from '@components/CustomViewProvider';

interface NewPluginButtonProps {
  drive: Resource<Server.Drive>;
}

const NewPluginButton: React.FC<NewPluginButtonProps> = ({ drive }) => {
  const configLabelId = useId();
  const [error, setError] = useState<string>();
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [metadata, setMetadata] = useState<PluginMetadata>();
  const [configValid, setConfigValid] = useState(true);
  const [config, setConfig] = useState<JSONValue>();
  const { refresh: refreshCustomViews } = useCustomViews();
  const { createPluginResource, addPluginToDrive } = useCreatePlugin();

  const reset = () => {
    setError(undefined);
    setFile(null);
    setMetadata(undefined);
    setConfig(undefined);
    setConfigValid(true);
    fileInputRef.current!.value = '';
  };

  const [dialogProps, show, hide] = useDialog({
    onCancel: reset,
    onSuccess: async () => {
      if (!metadata || !file) {
        return setError('Please fill in all fields');
      }

      try {
        const plugin = await createPluginResource({
          metadata,
          file,
          drive,
          config,
        });
        await addPluginToDrive(plugin, drive);
        await refreshCustomViews();
        reset();
      } catch (err) {
        toast.error('Failed to install plugin');
        console.error(err);
        reset();
      }
    },
  });

  const handleFileInputChange = async (
    e: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const targetFile = e.target.files?.[0];

    if (targetFile) {
      try {
        const readMetadata = await readZip(targetFile);
        setMetadata(readMetadata);
        setConfig(readMetadata.defaultConfig);
        setFile(targetFile);
        setError(undefined);
        show();
      } catch (err) {
        setError(err.message);
      }
    }
  };

  return (
    <>
      <label>
        <Button as='div'>
          <FaPlus aria-hidden /> <span>Upload Plugin</span>
        </Button>
        <input
          ref={fileInputRef}
          type='file'
          style={{ display: 'none' }}
          accept='application/zip'
          onChange={handleFileInputChange}
        />
      </label>
      {error && <p>{error}</p>}
      <Dialog {...dialogProps} width='800px'>
        <Dialog.Title>
          <h1>Add Plugin</h1>
        </Dialog.Title>
        <Dialog.Content>
          {metadata && (
            <Column>
              <div>
                <Row justify='space-between'>
                  <PluginName>
                    {metadata.namespace}/{metadata.name}
                  </PluginName>
                  <span>v{metadata.version}</span>
                </Row>
                <PluginAuthor>by {metadata.author}</PluginAuthor>
              </div>
              {metadata.description && (
                <DescriptionWrapper>
                  <Markdown text={metadata.description} />
                </DescriptionWrapper>
              )}
              <PluginPermissions permissions={metadata.permissions} />

              <Label id={configLabelId}>Config</Label>
              <JSONEditor
                labelId={configLabelId}
                initialValue={JSON.stringify(metadata.defaultConfig, null, 2)}
                onChange={val => {
                  try {
                    setConfig(JSON.parse(val));
                  } catch (e) {
                    // Do nothing
                  }
                }}
                schema={metadata.configSchema}
                showErrorStyling={!configValid}
                onValidationChange={setConfigValid}
              />
              {metadata.configSchema && (
                <ConfigReference schema={metadata.configSchema} />
              )}
            </Column>
          )}
          {!metadata && (
            <label>
              <Button as='div'>
                <FaPlus aria-hidden /> <span>Upload Plugin</span>
              </Button>
              <input
                type='file'
                style={{ display: 'none' }}
                accept='application/zip'
                onChange={handleFileInputChange}
              />
            </label>
          )}
        </Dialog.Content>
        <Dialog.Actions>
          <Button onClick={() => hide(false)} subtle>
            Cancel
          </Button>
          <Button
            onClick={() => hide(true)}
            disabled={!metadata || !configValid}
          >
            Install
          </Button>
        </Dialog.Actions>
      </Dialog>
    </>
  );
};

export default NewPluginButton;

const PluginName = styled.span`
  font-weight: bold;
`;

const DescriptionWrapper = styled.div`
  background-color: ${p => p.theme.colors.bg1};
  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};
`;

const PluginAuthor = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const Label = styled.label`
  font-weight: bold;
`;
