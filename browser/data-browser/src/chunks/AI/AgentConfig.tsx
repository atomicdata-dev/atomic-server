import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { Column } from '@components/Row';
import { FaPlus } from 'react-icons/fa6';
import { ModelSelect } from './ModelSelect/ModelSelect';
import { type AIAgent, type AIModelIdentifier } from './types';
import { useLocalStorage } from '@hooks/useLocalStorage';
import { SkeletonButton } from '@components/SkeletonButton';
import { MarkdownInput } from '@components/forms/MarkdownInput';
import { Checkbox, CheckboxLabel } from '@components/forms/Checkbox';
import { Input } from '@components/forms/InputStyles';
import { SliderInput } from '@components/forms/SliderInput';
import { useAISettings } from '@components/AI/AISettingsContext';
import { AgentConfigItem } from './AgentConfigItem';
import { ConfigEditorDialog } from './ConfigEditorDialog';
import atomicAgentPrompt from './system-prompts/atomic-agent.md?raw';
import Field from '@components/forms/Field';
import Markdown from '@components/datatypes/Markdown';

// Add this formatter at the top of the file, after imports
const temperatureFormatter = new Intl.NumberFormat(undefined, {
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});

const DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT = 80;

// Helper function to generate a unique ID
const generateId = () => {
  return `custom-user-agent.${Math.random().toString(36).substring(2, 11)}`;
};

interface AgentConfigTabProps {
  selectedAgent: AIAgent;
  onSelectAgent: (agent: AIAgent) => void;
}

const defaultNewAgent: Omit<AIAgent, 'id'> = {
  name: '',
  description: '',
  systemPrompt: '',
  availableTools: [],
  canReadAtomicData: false,
  canWriteAtomicData: false,
  ragEnabled: false,
  skillsEnabled: true,
  temperature: 0.1,
  autoCompactThresholdPercent: DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT,
};

const defaultAgents: AIAgent[] = [
  {
    name: 'Atomic Data Agent',
    id: 'dev.atomicdata.atomic-agent',
    description:
      "An agent that is specialized in helping you use AtomicServer. It takes context from what you're doing.",
    systemPrompt: atomicAgentPrompt,
    availableTools: ['dev.atomicdata.mcp.exa'],
    canReadAtomicData: true,
    canWriteAtomicData: true,
    ragEnabled: false,
    skillsEnabled: true,
    temperature: 0.1,
    autoCompactThresholdPercent: DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT,
  },
  {
    name: 'General Agent',
    id: 'dev.atomicdata.general-agent',
    description: "A basic agent that doesn't have any special purpose.",
    systemPrompt: `The current date is {{timestamp}}`,
    availableTools: ['dev.atomicdata.mcp.exa'],
    canReadAtomicData: false,
    canWriteAtomicData: false,
    ragEnabled: false,
    skillsEnabled: true,
    temperature: 0.1,
    autoCompactThresholdPercent: DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT,
  },
];

export const getDefaultAgent = (agentId: string) =>
  defaultAgents.find(agent => agent.id === agentId);

const mergeDefaultAgentFields = (agent: AIAgent): AIAgent => {
  const defaultAgent = getDefaultAgent(agent.id);

  if (!defaultAgent) {
    return agent;
  }

  return {
    ...agent,
    name: defaultAgent.name,
    description: defaultAgent.description,
    systemPrompt: defaultAgent.systemPrompt,
  };
};

export const useAIAgentConfig = () => {
  const [storedAgents, setAgents] = useLocalStorage<AIAgent[]>(
    'atomic.ai.agents',
    defaultAgents,
  );
  const agents = storedAgents.map(mergeDefaultAgentFields);
  const [defaultAgentId, setDefaultAgentId] = useLocalStorage<string>(
    'atomic.ai.defaultAgentId',
    agents[0]?.id || '',
  );

  const [agentChatIndex, setAgentChatIndex] = useLocalStorage<
    Record<string, string>
  >('atomic.ai.lastUsedAgentInChat', {});

  // Remember the last used agent in the sidebar but don't keep it
  const [lastUsedSidebarAgent, setLastUsedSidebarAgent] =
    useLocalStorage<string>(
      'atomic.ai.sidebar.lastUsedAgent',
      defaultAgentId,
      window.sessionStorage,
    );

  // Save agents to settings
  const saveAgents = (newAgents: AIAgent[]) => {
    setAgents(newAgents.map(mergeDefaultAgentFields));
  };

  const getInitialAgent = (sideBar: boolean, chatSubject?: string) => {
    if (sideBar) {
      return agents.find(a => a.id === lastUsedSidebarAgent) ?? agents[0];
    } else if (chatSubject) {
      const id = agentChatIndex[chatSubject] ?? defaultAgentId;

      return agents.find(a => a.id === id) ?? agents[0];
    }

    return agents.find(a => a.id === defaultAgentId) ?? agents[0];
  };

  const setLastUsedAgentForChat = (chatSubject: string, agentId: string) => {
    setAgentChatIndex({ ...agentChatIndex, [chatSubject]: agentId });
  };

  return {
    agents,
    saveAgents,
    defaultAgentId,
    setDefaultAgentId,
    setLastUsedAgentForChat,
    setLastUsedSidebarAgent,
    getInitialAgent,
  };
};

export const AgentConfigTab = ({
  selectedAgent,
  onSelectAgent,
}: AgentConfigTabProps) => {
  const { agents, saveAgents } = useAIAgentConfig();
  const { defaultChatModel } = useAISettings();
  const [editingAgent, setEditingAgent] = useState<AIAgent | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  const handleSaveAgent = () => {
    if (!editingAgent) return;

    const savedAgent = mergeDefaultAgentFields(editingAgent);
    const newAgents = isCreating
      ? [...agents, savedAgent]
      : agents.map((agent: AIAgent) =>
          // Use ID to identify which agent we're editing
          agent.id === savedAgent.id ? savedAgent : agent,
        );

    saveAgents(newAgents);

    // If we're editing the currently selected agent or creating a new one, update selection
    if (selectedAgent.id === savedAgent.id || isCreating) {
      onSelectAgent(savedAgent);
    }
  };

  const handleDeleteAgent = (agentToDelete: AIAgent) => {
    if (agents.length <= 1 || getDefaultAgent(agentToDelete.id)) {
      // Prevent deleting the last agent or built-in defaults.
      return;
    }

    const newAgents = agents.filter(
      (agent: AIAgent) => agent.id !== agentToDelete.id,
    );
    saveAgents(newAgents);

    // If we're deleting the currently selected agent, select the first available
    if (selectedAgent.id === agentToDelete.id) {
      onSelectAgent(newAgents[0]);
    }
  };

  const handleDuplicateAgent = (agentToDuplicate: AIAgent) => {
    const duplicatedAgent: AIAgent = {
      ...agentToDuplicate,
      id: generateId(),
      name: `${agentToDuplicate.name} - Copy`,
      availableTools: [...agentToDuplicate.availableTools],
      model: agentToDuplicate.model ? { ...agentToDuplicate.model } : undefined,
    };

    saveAgents([...agents, duplicatedAgent]);
    onSelectAgent(duplicatedAgent);
  };

  const handleCreateNewAgent = () => {
    setEditingAgent({
      ...defaultNewAgent,
      id: generateId(),
      model: defaultChatModel,
    });
    setIsCreating(true);
  };

  const handleEditAgent = (agent: AIAgent) => {
    setEditingAgent({ ...agent });
    setIsCreating(false);
  };

  const handleDialogClosed = () => {
    setEditingAgent(null);
    setIsCreating(false);
  };

  return (
    <Column>
      <AgentsList role='radiogroup' aria-label='AI Agents'>
        {agents.map((agent: AIAgent) => (
          <AgentConfigItem
            key={agent.id}
            agent={agent}
            selected={selectedAgent.id === agent.id}
            onSelect={onSelectAgent}
            onEdit={handleEditAgent}
            onDelete={handleDeleteAgent}
            onDuplicate={handleDuplicateAgent}
            canDelete={!getDefaultAgent(agent.id)}
          />
        ))}
      </AgentsList>

      <CreateButton onClick={handleCreateNewAgent}>
        <FaPlus title='' />
        <span>Create New Agent</span>
      </CreateButton>

      <ConfigEditorDialog
        open={!!editingAgent}
        title={isCreating ? 'New Agent' : 'Edit Agent'}
        saveLabel={isCreating ? 'Create Agent' : 'Save Changes'}
        canSave={!!editingAgent?.name.trim()}
        onSave={handleSaveAgent}
        onClosed={handleDialogClosed}
      >
        {editingAgent && (
          <AgentForm
            agent={editingAgent}
            isDefaultAgent={!!getDefaultAgent(editingAgent.id)}
            onChange={setEditingAgent}
          />
        )}
      </ConfigEditorDialog>
    </Column>
  );
};

interface AgentFormProps {
  agent: AIAgent;
  isDefaultAgent: boolean;
  onChange: (agent: AIAgent) => void;
}

const AgentForm = ({ agent, isDefaultAgent, onChange }: AgentFormProps) => {
  const { mcpServers, defaultChatModel } = useAISettings();

  const handleChange = (
    field: keyof AIAgent,
    value: string | boolean | number | AIModelIdentifier | undefined,
  ) => {
    onChange({
      ...agent,
      [field]: value,
    });
  };

  const onToggleTool = (toolId: string) => {
    onChange({
      ...agent,
      availableTools: agent.availableTools.includes(toolId)
        ? agent.availableTools.filter(t => t !== toolId)
        : [...agent.availableTools, toolId],
    });
  };

  useEffect(() => {
    // Check if the agent has any tools that are not available any more.
    const currentlyAvailableServers = mcpServers.map(s => s.id);
    const tools = agent.availableTools.filter(tool =>
      currentlyAvailableServers.includes(tool),
    );

    if (tools.length !== agent.availableTools.length) {
      onChange({
        ...agent,
        availableTools: tools,
      });
    }
  }, [agent, mcpServers, onChange]);

  const enforceToolSupport =
    agent.availableTools.length > 0 ||
    agent.canReadAtomicData ||
    agent.canWriteAtomicData;

  return (
    <FormContainer>
      <StyledField label='Name' fieldId='agent-name'>
        <Input
          id='agent-name'
          required
          max={50}
          readOnly={isDefaultAgent}
          value={agent.name}
          onChange={e => handleChange('name', e.target.value)}
          placeholder='Agent name'
        />
      </StyledField>

      <StyledField label='Description' fieldId='agent-description'>
        <Input
          id='agent-description'
          readOnly={isDefaultAgent}
          value={agent.description}
          onChange={e => handleChange('description', e.target.value)}
          placeholder='Agent description'
        />
      </StyledField>

      <StyledField
        label='System Prompt'
        fieldId='agent-system-prompt'
        helper='The system prompt that defines how the agent behaves. You can use the following placeholders: {{timestamp}} - the current date and time, {{drive}} - subject of the current drive, {{drive-structure}} - a tree of resources on the drive, {{custom-classes}} - a list of classes defined on the current drive.'
      >
        {isDefaultAgent ? (
          <SystemPromptPreview id='agent-system-prompt'>
            <Markdown text={agent.systemPrompt} maxLength={Infinity} />
          </SystemPromptPreview>
        ) : (
          <MarkdownInput
            key={agent.id}
            id='agent-system-prompt'
            initialContent={agent.systemPrompt}
            onChange={content => handleChange('systemPrompt', content)}
            placeholder='System prompt that defines how the agent behaves'
          />
        )}
      </StyledField>

      <StyledField label='Atomic Data Access' multiInput>
        <CheckboxLabel>
          <Checkbox
            checked={agent.canReadAtomicData}
            onChange={checked => handleChange('canReadAtomicData', checked)}
          />
          <span>Read</span>
        </CheckboxLabel>
        <CheckboxLabel>
          <Checkbox
            checked={agent.canWriteAtomicData}
            onChange={checked => handleChange('canWriteAtomicData', checked)}
          />
          <span>Write</span>
        </CheckboxLabel>
        <CheckboxLabel>
          <Checkbox
            checked={agent.ragEnabled}
            onChange={checked => handleChange('ragEnabled', checked)}
          />
          <span>
            RAG, Automatically provide context from your knowledge base based on
            your prompt.
          </span>
        </CheckboxLabel>
      </StyledField>
      <StyledField label='Tools' multiInput>
        <ToolList>
          {mcpServers.map(server => (
            <li key={server.id}>
              <CheckboxLabel>
                <Checkbox
                  checked={agent.availableTools.includes(server.id)}
                  onChange={() => onToggleTool(server.id)}
                />
                {server.name}
              </CheckboxLabel>
            </li>
          ))}
          {mcpServers.length === 0 && (
            <li>
              <SubtleText>No MCP servers configured.</SubtleText>
            </li>
          )}
        </ToolList>
      </StyledField>
      <StyledField
        label='Skills'
        multiInput
        helper='Give the agent access to skills that provide domain-specific knowledge and guidance. A list of skills will be added to the end of the system prompt.'
      >
        <CheckboxLabel>
          <Checkbox
            checked={agent.skillsEnabled ?? true}
            onChange={checked => handleChange('skillsEnabled', checked)}
          />
          <span>Enable skills</span>
        </CheckboxLabel>
      </StyledField>

      <StyledField label='Model' multiInput>
        <CheckboxLabel style={{ marginBottom: '0.5rem' }}>
          <Checkbox
            checked={!agent.model}
            onChange={checked => {
              handleChange('model', checked ? undefined : defaultChatModel);
            }}
          />
          <span>Use Default Model</span>
        </CheckboxLabel>
        {agent.model && (
          <ModelSelect
            defaultModel={agent.model}
            onSelect={model => handleChange('model', model)}
            enforceToolSupport={enforceToolSupport}
          />
        )}
      </StyledField>

      <StyledField
        label='Temperature'
        fieldId='agent-temperature'
        helper='Trade accuracy for creativity'
      >
        <SliderInput
          id='agent-temperature'
          min={0}
          max={2}
          step={0.01}
          value={agent.temperature ?? 0}
          onChange={value => handleChange('temperature', value)}
          formatValue={temperatureFormatter.format}
          numberAriaLabel='Temperature value'
        />
      </StyledField>

      <StyledField
        label='Auto-compact threshold'
        labelPrefix={
          <Checkbox
            checked={
              (agent.autoCompactThresholdPercent ??
                DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT) > 0
            }
            onChange={checked =>
              handleChange(
                'autoCompactThresholdPercent',
                checked ? DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT : 0,
              )
            }
            aria-label='Enable auto-compact'
          />
        }
        fieldId='agent-auto-compact-threshold'
        helper='Automatically compact the conversation when input tokens exceed this percentage of the selected model context window. Manual /compact still works when disabled.'
      >
        {(agent.autoCompactThresholdPercent ??
          DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT) === 0 ? (
          <SubtleText>Don&apos;t auto compact conversation</SubtleText>
        ) : (
          <SliderInput
            id='agent-auto-compact-threshold'
            min={1}
            max={100}
            step={1}
            suffix='%'
            value={
              agent.autoCompactThresholdPercent ??
              DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT
            }
            onChange={value =>
              handleChange('autoCompactThresholdPercent', value)
            }
            numberAriaLabel='Auto-compact threshold percent'
          />
        )}
      </StyledField>
    </FormContainer>
  );
};

// Styled components
const AgentsList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0;
  margin-top: ${p => p.theme.size(2)};
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(2)};
`;

const CreateButton = styled(SkeletonButton)`
  width: 100%;
  padding: ${p => p.theme.size(2)} ${p => p.theme.size(3)};
  height: 3rem;
`;

const FormContainer = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(3)};
`;

const StyledField = styled(Field)`
  & ${Field.Label} {
    font-size: 0.875rem;
  }
`;

const SystemPromptPreview = styled.div`
  background-color: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  box-shadow: 0 0 0 1px ${p => p.theme.colors.bg2};
  max-height: 30rem;
  overflow: auto;
  padding: ${p => p.theme.size()};
`;

const ToolList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0;

  li {
    list-style: none;
    margin: 0;
    padding: 0;
  }
`;

const SubtleText = styled.p`
  font-size: 0.875rem;
  color: ${p => p.theme.colors.textLight};
`;
