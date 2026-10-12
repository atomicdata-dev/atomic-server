// @wc-ignore-file
// An AI message as one chat log entry (planning/chat-log.md, "AI chat"): the
// parts are inlined as JSON instead of one resource each. The shape is the one
// `ai_chat_migration.rs` writes for old chats, so both read the same way.
import { isToolUIPart, type UIMessage } from 'ai';
import { newContextItem } from '@components/AI/AISidebarContext';
import { ai, type ChatLogEntry } from '@tomic/react';
import { restoreToolPart, toolPartValues } from './toolHistory';
import type {
  AIAtomicResourceMessageContext,
  AIMCPResourceMessageContext,
  AIMessageContext,
  AtomicUIMessage,
} from './types';

type Part = AtomicUIMessage['parts'][number];

const ROLES = ['user', 'assistant', 'system', 'summary'] as const;

/** A part as it is stored: only what is needed to show it and to resend it. */
export function partToJson(part: Part): Record<string, unknown> | undefined {
  if (part.type === 'text' || part.type === 'reasoning') {
    return { type: part.type, text: part.text };
  }

  if (part.type === 'file') {
    return {
      type: 'file',
      url: part.url,
      mediaType: part.mediaType,
      ...(part.filename ? { filename: part.filename } : {}),
    };
  }

  if (part.type === 'source-url') {
    return {
      type: 'source-url',
      url: part.url,
      ...(part.title ? { title: part.title } : {}),
    };
  }

  if (isToolUIPart(part)) {
    const values = toolPartValues(part);

    return {
      ...restoreToolPart({
        toolName: values[ai.properties.toolName],
        toolId: values[ai.properties.toolId],
        toolInput: values[ai.properties.toolInput],
        toolOutput: values[ai.properties.toolOutput],
        toolResultIsError: values[ai.properties.toolResultIsError],
      }),
    };
  }

  // `step-start` and parts of kinds the app never stored.
  return undefined;
}

function contextToJson(context: AIMessageContext): object | undefined {
  // Skill context is ephemeral: it is already inlined into the outgoing message.
  if (context.type === 'skill') return undefined;

  if (context.type === 'atomic-resource') {
    return { type: 'atomic-resource', subject: context.subject };
  }

  return {
    type: 'mcp-resource',
    name: context.name,
    uri: context.uri,
    serverId: context.serverId,
    ...(context.mimetype ? { mimetype: context.mimetype } : {}),
  };
}

/** The entry for a UI message, written by `author` at `c`. */
export function messageToEntry(
  message: AtomicUIMessage,
  author: string,
  c: number,
): ChatLogEntry {
  // Summary messages are stored with role 'summary' whatever their UI role.
  const role = message.metadata?.isSummary ? 'summary' : message.role;
  const parts = message.parts.flatMap(p => partToJson(p) ?? []);
  const context = (message.metadata?.userContext ?? []).flatMap(
    ctx => contextToJson(ctx) ?? [],
  );
  const entry: ChatLogEntry = {
    a: author,
    t: '',
    c,
    role,
    parts: JSON.stringify(parts),
  };

  if (context.length > 0) entry.ctx = JSON.stringify(context);

  if (message.metadata?.serverContext) {
    entry.sc = message.metadata.serverContext;
  }

  if (message.role === 'assistant' && message.metadata?.error !== undefined) {
    entry.err = message.metadata.error;
  }

  return entry;
}

function parseJsonList(value: unknown): unknown[] {
  if (typeof value !== 'string') return [];

  try {
    const parsed: unknown = JSON.parse(value);

    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function restoreContext(raw: unknown): AIMessageContext | undefined {
  const item = raw as Record<string, unknown> | null;

  if (item?.type === 'atomic-resource' && typeof item.subject === 'string') {
    return newContextItem<AIAtomicResourceMessageContext>({
      type: 'atomic-resource',
      subject: item.subject,
    });
  }

  if (item?.type === 'mcp-resource') {
    return newContextItem<AIMCPResourceMessageContext>({
      type: 'mcp-resource',
      name: String(item.name ?? ''),
      uri: String(item.uri ?? ''),
      serverId: String(item.serverId ?? ''),
      mimetype: typeof item.mimetype === 'string' ? item.mimetype : undefined,
    });
  }

  return undefined;
}

function restorePart(raw: unknown): Part | undefined {
  const part = raw as Record<string, unknown> | null;

  if (!part || typeof part.type !== 'string') return undefined;

  switch (part.type) {
    case 'text':
    case 'reasoning':
      return { type: part.type, text: String(part.text ?? '') };
    case 'file':
      return {
        type: 'file',
        url: String(part.url ?? ''),
        mediaType: String(part.mediaType ?? ''),
        filename: typeof part.filename === 'string' ? part.filename : undefined,
      };
    case 'source-url':
      return {
        type: 'source-url',
        sourceId: crypto.randomUUID(),
        url: String(part.url ?? ''),
        title: typeof part.title === 'string' ? part.title : undefined,
      };
    default:
      return part.type.startsWith('tool-')
        ? (part as unknown as Part)
        : undefined;
  }
}

/** The UI message an entry stands for; `id` is the entry id. */
export function entryToMessage(
  id: string,
  entry: ChatLogEntry,
): AtomicUIMessage | undefined {
  const role = entry.role;

  if (typeof role !== 'string' || !ROLES.includes(role as never)) {
    return undefined;
  }

  const parts = parseJsonList(entry.parts).flatMap(p => restorePart(p) ?? []);
  const message: AtomicUIMessage = {
    id,
    role: role === 'summary' ? 'user' : (role as UIMessage['role']),
    parts,
  };

  if (role === 'summary') {
    message.metadata = { isSummary: true };

    return message;
  }

  if (role === 'user') {
    const context = parseJsonList(entry.ctx).flatMap(
      c => restoreContext(c) ?? [],
    );

    if (context.length > 0) {
      message.metadata = { ...message.metadata, userContext: context };
    }

    if (typeof entry.sc === 'string') {
      message.metadata = { ...message.metadata, serverContext: entry.sc };
    }
  }

  if (role === 'assistant' && typeof entry.err === 'string') {
    message.metadata = { ...message.metadata, error: entry.err };
  }

  return message;
}
