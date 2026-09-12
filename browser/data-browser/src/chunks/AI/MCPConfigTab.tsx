import { useEffect, useId, useState } from 'react';
import { randomUUID } from '@tomic/lib';
import { createPortal } from 'react-dom';
import { styled } from 'styled-components';
import { Row, Column } from '@components/Row';
import { FaPlus, FaPen, FaTrash } from 'react-icons/fa6';
import { Button } from '@components/Button';
import { IconButton } from '@components/IconButton/IconButton';
import { SkeletonButton } from '@components/SkeletonButton';
import { BasicSelect } from '@components/forms/BasicSelect';
import { Input } from '@components/forms/InputStyles';
import Field from '@components/forms/Field';
import { useAISettings } from '@components/AI/AISettingsContext';
import type { MCPServer } from './types';
import { getDefaultMCPServer } from './defaultMCPServers';

const generateId = () => randomUUID();

const defaultNewServer: MCPServer = {
  id: '',
  name: '',
  url: '',
  transport: 'http',
};

type MCPHeaderRow = {
  id: string;
  key: string;
  value: string;
};

const headersToRows = (headers: MCPServer['headers']): MCPHeaderRow[] =>
  Object.entries(headers ?? {}).map(([key, value]) => ({
    id: generateId(),
    key,
    value,
  }));

const rowsToHeaders = (
  rows: Array<Pick<MCPHeaderRow, 'key' | 'value'>>,
): MCPServer['headers'] => {
  const headers = rows.reduce<Record<string, string>>((acc, row) => {
    const key = row.key.trim();
    const value = row.value.trim();

    if (key && value) {
      acc[key] = value;
    }

    return acc;
  }, {});

  return Object.keys(headers).length > 0 ? headers : undefined;
};

interface MCPConfigTabProps {
  actionPortalElement: HTMLElement | null;
  onActionsVisibleChange: (visible: boolean) => void;
}

export const MCPConfigTab = ({
  actionPortalElement,
  onActionsVisibleChange,
}: MCPConfigTabProps) => {
  const { mcpServers, setMcpServers } = useAISettings();
  const [editingServer, setEditingServer] = useState<MCPServer | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  useEffect(() => {
    return () => onActionsVisibleChange(false);
  }, [onActionsVisibleChange]);

  const handleSaveServer = () => {
    if (!editingServer) return;

    if (!editingServer.name.trim() || !editingServer.url.trim()) return;

    const headers = rowsToHeaders(
      Object.entries(editingServer.headers ?? {}).map(([key, value]) => ({
        key,
        value,
      })),
    );
    const { headers: _headers, ...serverFields } = editingServer;
    const serverToSave: MCPServer = {
      ...serverFields,
      name: editingServer.name.trim(),
      url: editingServer.url.trim(),
      ...(headers ? { headers } : {}),
    };

    const newServers = isCreating
      ? [...mcpServers, serverToSave]
      : mcpServers.map(s => (s.id === serverToSave.id ? serverToSave : s));

    setMcpServers(newServers);
    setEditingServer(null);
    setIsCreating(false);
    onActionsVisibleChange(false);
  };

  const handleDeleteServer = (serverToDelete: MCPServer) => {
    if (getDefaultMCPServer(serverToDelete.id)) {
      return;
    }

    setMcpServers(mcpServers.filter(s => s.id !== serverToDelete.id));
  };

  const handleCreateNewServer = () => {
    setEditingServer({ ...defaultNewServer, id: generateId() });
    setIsCreating(true);
    onActionsVisibleChange(true);
  };

  const handleEditServer = (server: MCPServer) => {
    setEditingServer({ ...server });
    setIsCreating(false);
    onActionsVisibleChange(true);
  };

  const handleCancel = () => {
    setEditingServer(null);
    setIsCreating(false);
    onActionsVisibleChange(false);
  };

  return (
    <>
      {editingServer ? (
        <Column>
          <ServerForm
            key={editingServer.id}
            server={editingServer}
            onChange={setEditingServer}
          />
        </Column>
      ) : (
        <Column>
          <ServerList role='list' aria-label='MCP Servers'>
            {mcpServers.map(server => {
              const headerCount = Object.keys(server.headers ?? {}).length;
              const isDefaultServer = !!getDefaultMCPServer(server.id);

              return (
                <ServerItem key={server.id}>
                  <Column gap='0.25rem'>
                    <strong>{server.name}</strong>
                    <SubtleText>{server.url}</SubtleText>
                    <SubtleText>Transport: {server.transport}</SubtleText>
                    {isDefaultServer && <SubtleText>Default server</SubtleText>}
                    {headerCount > 0 && (
                      <SubtleText>
                        {headerCount} custom header
                        {headerCount === 1 ? '' : 's'}
                      </SubtleText>
                    )}
                  </Column>
                  <Row>
                    <IconButton
                      title='Edit Server'
                      onClick={() => handleEditServer(server)}
                    >
                      <FaPen />
                    </IconButton>
                    {!isDefaultServer && (
                      <IconButton
                        title='Delete Server'
                        color='alert'
                        onClick={() => handleDeleteServer(server)}
                      >
                        <FaTrash />
                      </IconButton>
                    )}
                  </Row>
                </ServerItem>
              );
            })}
            {mcpServers.length === 0 && (
              <SubtleText>No MCP servers configured yet.</SubtleText>
            )}
          </ServerList>

          <CreateButton onClick={handleCreateNewServer}>
            <FaPlus title='' /> Add New Server
          </CreateButton>
        </Column>
      )}
      {editingServer &&
        actionPortalElement &&
        createPortal(
          <>
            <Button subtle onClick={handleCancel}>
              Cancel
            </Button>
            <Button
              onClick={handleSaveServer}
              disabled={!editingServer.name.trim() || !editingServer.url.trim()}
            >
              {isCreating ? 'Create Server' : 'Save Changes'}
            </Button>
          </>,
          actionPortalElement,
        )}
    </>
  );
};

interface ServerFormProps {
  server: MCPServer;
  onChange: (server: MCPServer) => void;
}

const ServerForm = ({ server, onChange }: ServerFormProps) => {
  const nameId = useId();
  const urlId = useId();
  const transportId = useId();
  const [headerRows, setHeaderRows] = useState<MCPHeaderRow[]>(() =>
    headersToRows(server.headers),
  );

  const updateServerHeaders = (rows: MCPHeaderRow[]) => {
    const headers = rowsToHeaders(rows);

    onChange({
      ...server,
      headers,
    });
  };

  const handleHeaderChange = (
    rowId: string,
    field: 'key' | 'value',
    value: string,
  ) => {
    const nextRows = headerRows.map(row =>
      row.id === rowId ? { ...row, [field]: value } : row,
    );

    setHeaderRows(nextRows);
    updateServerHeaders(nextRows);
  };

  const handleAddHeader = () => {
    setHeaderRows(rows => [
      ...rows,
      {
        id: generateId(),
        key: '',
        value: '',
      },
    ]);
  };

  const handleRemoveHeader = (rowId: string) => {
    const nextRows = headerRows.filter(row => row.id !== rowId);

    setHeaderRows(nextRows);
    updateServerHeaders(nextRows);
  };

  return (
    <Column>
      <Field
        helperAlwaysVisible
        required
        label='Name'
        helper='A friendly name for this MCP server'
        fieldId={nameId}
      >
        <Input
          required
          value={server.name}
          onChange={e => onChange({ ...server, name: e.target.value })}
          placeholder='e.g., my-mcp-server'
          id={nameId}
        />
      </Field>

      <Field
        helperAlwaysVisible
        required
        label='URL'
        helper='The URL where the MCP server can be reached'
        fieldId={urlId}
      >
        <Input
          required
          type='url'
          inputMode='url'
          pattern='https?://.*'
          value={server.url}
          onChange={e => onChange({ ...server, url: e.target.value })}
          placeholder='https://example.com/mcp'
          id={urlId}
        />
      </Field>

      <Field
        helperAlwaysVisible
        label='Transport'
        helper='The transport protocol used to communicate with the server'
        fieldId={transportId}
      >
        <BasicSelect
          id={transportId}
          value={server.transport}
          onChange={e =>
            onChange({
              ...server,
              transport: e.target.value as 'http' | 'sse',
            })
          }
          title='Select transport type'
        >
          <option value='http'>HTTP</option>
          <option value='sse'>SSE</option>
        </BasicSelect>
      </Field>

      <Field
        helperAlwaysVisible
        label='Headers'
        helper='Optional HTTP headers to send when connecting to this MCP server'
        multiInput
      >
        <HeaderRows>
          {headerRows.map((row, index) => (
            <HeaderRowContainer key={row.id} fullWidth center>
              <Input
                aria-label={`Header ${index + 1} key`}
                value={row.key}
                onChange={e =>
                  handleHeaderChange(row.id, 'key', e.target.value)
                }
                placeholder='Header key'
              />
              <Input
                aria-label={`Header ${index + 1} value`}
                type='password'
                value={row.value}
                onChange={e =>
                  handleHeaderChange(row.id, 'value', e.target.value)
                }
                placeholder='Header value'
              />
              <IconButton
                title='Remove header'
                color='alert'
                onClick={() => handleRemoveHeader(row.id)}
              >
                <FaTrash />
              </IconButton>
            </HeaderRowContainer>
          ))}
          {headerRows.length === 0 && (
            <SubtleText>No custom headers configured.</SubtleText>
          )}
        </HeaderRows>
        <Button subtle onClick={handleAddHeader}>
          <FaPlus title='' /> Add header
        </Button>
      </Field>
    </Column>
  );
};

const ServerList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size()};
`;

const ServerItem = styled.li`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: ${p => p.theme.size(2)};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  margin: 0;
`;

const CreateButton = styled(SkeletonButton)`
  height: 3rem;
`;

const HeaderRows = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(2)};
  margin-bottom: ${p => p.theme.size(2)};
`;

const HeaderRowContainer = styled(Row)`
  align-items: center;
`;

const SubtleText = styled.p`
  margin: 0;
  font-size: 0.875rem;
  color: ${p => p.theme.colors.textLight};
`;
