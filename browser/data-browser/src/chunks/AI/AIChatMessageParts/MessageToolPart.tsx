import { IntegrationActionReview } from './IntegrationActionReview';
import { getToolName, type DynamicToolUIPart, type ToolUIPart } from 'ai';
import { styled } from 'styled-components';
import {
  FaBook,
  FaDatabase,
  FaEye,
  FaGraduationCap,
  FaGlobe,
  FaMagnifyingGlass,
  FaPencil,
  FaPlus,
  FaWrench,
} from 'react-icons/fa6';
import { Details } from '@components/Details';
import { Shimmer } from '@components/Shimmer';
import { PartSummary } from './PartSummary';
import { SearchToolMessageContent } from './SearchToolMessageContent';
import { TOOL_NAMES } from '../useAtomicTools';
import { InlineFormattedResourceList } from '@components/InlineFormattedResourceList';
import { useResource } from '@tomic/react';
import { MCP_TOOL_NAMES } from '../defaultMCPServers';
import { core, Client } from '@tomic/lib';
import { tryExpandRef } from '@helpers/subjectRefs';

interface ToolMessageProps {
  part: ToolUIPart | DynamicToolUIPart;
}

export const MessageToolPart: React.FC<ToolMessageProps> = ({ part }) => {
  const toolName = getToolName(part);

  const Icon = getIcon(toolName);

  if (part.state === 'input-streaming' || part.state === 'input-available') {
    return (
      <Shimmer>
        <PartSummary>
          <Icon />
          <ToolTitle toolName={toolName} part={part} />
        </PartSummary>
      </Shimmer>
    );
  }

  if (
    part.state === 'output-available' &&
    toolName === TOOL_NAMES.CALL_INTEGRATION_ACTION
  ) {
    const output = part.output as {
      status?: string;
      drive?: string;
      integration?: string;
      proposal?: { id?: string };
    } | null;

    if (
      output?.status === 'needs_review' &&
      typeof output.drive === 'string' &&
      typeof output.integration === 'string' &&
      typeof output.proposal?.id === 'string'
    ) {
      return (
        <IntegrationActionReview
          drive={output.drive}
          plugin={output.integration}
          id={output.proposal.id}
        />
      );
    }
  }

  if (part.state === 'output-available') {
    return (
      <Details
        noIndent
        titleButton={
          <PartSummary $interactive>
            <Icon />
            <ToolTitle toolName={toolName} part={part} />
          </PartSummary>
        }
      >
        {toolName === TOOL_NAMES.SEMANTIC_SEARCH ? (
          <SearchToolMessageContent
            output={part.output}
            query={
              isVectorSearchArgs(part.input) ? part.input.query : undefined
            }
          />
        ) : (
          <StyledPre>{JSON.stringify(part.output, null, 2)}</StyledPre>
        )}
      </Details>
    );
  }

  return null;
};

const getIcon = (toolName: string) => {
  switch (toolName) {
    case MCP_TOOL_NAMES.EXA_WEB_SEARCH:
      return FaGlobe;
    case TOOL_NAMES.SEMANTIC_SEARCH:
      return FaMagnifyingGlass;
    case TOOL_NAMES.QUERY:
      return FaDatabase;
    case TOOL_NAMES.GET_ATOMIC_RESOURCE:
      return FaEye;
    case TOOL_NAMES.READ_SKILL:
    case TOOL_NAMES.READ_SKILL_REFERENCE:
      return FaGraduationCap;
    case TOOL_NAMES.GET_SCHEMA:
    case TOOL_NAMES.GET_USER_CLASSES:
    case TOOL_NAMES.DESCRIBE_DASHBOARD:
      return FaBook;
    case TOOL_NAMES.EDIT_ATOMIC_RESOURCE:
    case TOOL_NAMES.EDIT_DOCUMENT_RESOURCE:
    case TOOL_NAMES.CONFIGURE_BLOCK:
      return FaPencil;
    case TOOL_NAMES.CREATE_RESOURCE:
    case TOOL_NAMES.CREATE_TABLE:
    case TOOL_NAMES.CREATE_DASHBOARD:
      return FaPlus;
    default:
      return FaWrench;
  }
};

const ToolTitle = ({
  toolName,
  part,
}: {
  toolName: string;
  part: ToolUIPart | DynamicToolUIPart;
}) => {
  const args = part.input as unknown;

  if (toolName === MCP_TOOL_NAMES.EXA_WEB_SEARCH) {
    return <span>Searching online</span>;
  }

  if (toolName === TOOL_NAMES.SEMANTIC_SEARCH && isVectorSearchArgs(args)) {
    return <span>{args.description}</span>;
  }

  if (toolName === TOOL_NAMES.GET_ATOMIC_RESOURCE && isFetchArgs(args)) {
    return <FetchResourceTitle subjects={args.subjects} />;
  }

  if (toolName === TOOL_NAMES.EDIT_ATOMIC_RESOURCE && isEditArgs(args)) {
    return <EditTitle property={args.property} subject={args.subject} />;
  }

  if (
    toolName === TOOL_NAMES.EDIT_DOCUMENT_RESOURCE &&
    isEditDocumentArgs(args)
  ) {
    return <EditDocumentTitle subject={args.subject} />;
  }

  if (toolName === TOOL_NAMES.QUERY && isQueryArgs(args)) {
    return <span>{args.description}</span>;
  }

  if (toolName === TOOL_NAMES.GET_SCHEMA && isGetSchemaArgs(args)) {
    if (args.subject) {
      return (
        <span>
          Reading <ResourceTitle subject={args.subject} /> schema
        </span>
      );
    }

    return <span>Reading schema</span>;
  }

  if (toolName === TOOL_NAMES.GET_USER_CLASSES) {
    return <span>Listing user classes</span>;
  }

  if (toolName === TOOL_NAMES.CREATE_RESOURCE && isCreateResourceArgs(args)) {
    return <CreateResourceTitle jsonAD={args.jsonAD} />;
  }

  if (toolName === TOOL_NAMES.CREATE_TABLE && isCreateTableArgs(args)) {
    return (
      <span>
        Creating table <Name>{args.name}</Name>
      </span>
    );
  }

  if (toolName === TOOL_NAMES.READ_SKILL && isReadSkillArgs(args)) {
    return (
      <span>
        Loading skill: <Name>{args.name.trim()}</Name>
      </span>
    );
  }

  if (
    toolName === TOOL_NAMES.READ_SKILL_REFERENCE &&
    isReadSkillReferenceArgs(args)
  ) {
    return (
      <span>
        Loading skill: <Name>{args.name.trim()}</Name>
        {' · '}
        <Name>{args.path.trim()}</Name>
      </span>
    );
  }

  if (toolName === TOOL_NAMES.DELETE_RESOURCE) {
    return <span>Deleting resource</span>;
  }

  if (toolName === TOOL_NAMES.FAVORITE_RESOURCE) {
    return <span>Toggling favorite</span>;
  }

  if (toolName === TOOL_NAMES.OPEN_SHARE_SETTINGS) {
    return <span>Opening share settings</span>;
  }

  if (toolName === TOOL_NAMES.SHOW_HISTORY) {
    return <span>Opening history</span>;
  }

  return <span>{toolName}</span>;
};

const FetchResourceTitle = ({ subjects }: { subjects: string[] }) => {
  return (
    <span>
      <span>Reading</span>{' '}
      <InlineFormattedResourceList
        subjects={subjects}
        RenderComp={ResourceTitle}
      />
    </span>
  );
};

const ResourceTitle = ({ subject: subjectOrRef }: { subject: string }) => {
  // Tool args may carry short `#refs` instead of full subjects.
  const subject = tryExpandRef(subjectOrRef) ?? subjectOrRef;

  // Some models stream tool inputs, that means that the subject is often not valid at the start.
  return Client.isValidSubject(subject) ? (
    <ResourceTitleInner subject={subject} />
  ) : (
    // Just render the subject if it's not a valid url yet.
    subject
  );
};

const ResourceTitleInner = ({ subject }: { subject: string }) => {
  const resource = useResource(subject);

  return (
    <Name>
      {resource.title.slice(0, 20)}
      {resource.title.length > 20 ? '...' : ''}
    </Name>
  );
};

const CreateResourceTitle = ({ jsonAD }: { jsonAD: string }) => {
  let name = 'resource';
  let count: number | undefined;

  try {
    const data = JSON.parse(jsonAD);

    if (Array.isArray(data)) {
      count = data.length;
    } else {
      name =
        data[core.properties.name] ??
        data[core.properties.shortname] ??
        'resource';
    }
  } catch {
    // Invalid JSON-AD, let the AI handle it.
  }

  if (count !== undefined) {
    return (
      <span>
        <span>Creating</span> <Name>{count} resources</Name>
      </span>
    );
  }

  return (
    <span>
      <span>Creating</span> <Name>{name}</Name>
    </span>
  );
};

const EditTitle = ({
  property,
  subject,
}: {
  property: string;
  subject: string;
}) => {
  const propertyResource = useResource(tryExpandRef(property) ?? property);

  return (
    <span>
      <span>Editing {propertyResource.title} on</span>{' '}
      <ResourceTitle subject={subject} />
    </span>
  );
};

const EditDocumentTitle = ({ subject }: { subject: string }) => {
  return (
    <span>
      <span>Editing</span> <ResourceTitle subject={subject} />
    </span>
  );
};

function isVectorSearchArgs(
  args: unknown,
): args is { query: string; description: string } {
  return (
    typeof args === 'object' &&
    args !== null &&
    'query' in args &&
    'description' in args
  );
}

function isQueryArgs(args: unknown): args is {
  description: string;
  filters: Record<string, unknown>;
  limit: number;
} {
  return typeof args === 'object' && args !== null && 'description' in args;
}

function isEditArgs(
  args: unknown,
): args is { subject: string; property: string; value: unknown } {
  return (
    typeof args === 'object' &&
    args !== null &&
    'subject' in args &&
    'property' in args &&
    'value' in args
  );
}

function isEditDocumentArgs(
  args: unknown,
): args is { subject: string; instruction: string; edit: string } {
  return (
    typeof args === 'object' &&
    args !== null &&
    'subject' in args &&
    'instruction' in args &&
    'edit' in args
  );
}

function isGetSchemaArgs(args: unknown): args is { subject?: string } {
  return typeof args === 'object' && args !== null;
}

function isFetchArgs(args: unknown): args is { subjects: string[] } {
  return (
    typeof args === 'object' &&
    args !== null &&
    'subjects' in args &&
    Array.isArray((args as { subjects?: unknown }).subjects)
  );
}

function isCreateResourceArgs(args: unknown): args is { jsonAD: string } {
  return typeof args === 'object' && args !== null && 'jsonAD' in args;
}

function isCreateTableArgs(args: unknown): args is { name: string } {
  return (
    typeof args === 'object' &&
    args !== null &&
    'name' in args &&
    typeof (args as { name: unknown }).name === 'string'
  );
}

function isReadSkillArgs(args: unknown): args is { name: string } {
  return (
    typeof args === 'object' &&
    args !== null &&
    'name' in args &&
    typeof (args as { name: unknown }).name === 'string'
  );
}

function isReadSkillReferenceArgs(
  args: unknown,
): args is { name: string; path: string } {
  return (
    typeof args === 'object' &&
    args !== null &&
    'name' in args &&
    'path' in args &&
    typeof (args as { name: unknown }).name === 'string' &&
    typeof (args as { path: unknown }).path === 'string'
  );
}

const StyledPre = styled.pre`
  background-color: ${p => p.theme.colors.bg};
  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};
  overflow-x: auto;
  code {
    font-family: Monaco, monospace;
    font-size: 0.8em;
  }
`;

const Name = styled.span`
  color: ${p => p.theme.colors.textLight};
`;
