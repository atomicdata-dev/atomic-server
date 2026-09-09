import { EditorContent, useEditor, type JSONContent } from '@tiptap/react';
import { styled } from 'styled-components';
import StarterKit from '@tiptap/starter-kit';
import Mention from '@tiptap/extension-mention';
import FileHandler from '@tiptap/extension-file-handler';
import { TiptapContextProvider } from '../TiptapContext';
import { EditorWrapperBase } from '../EditorWrapperBase';
import { searchSuggestionBuilder } from './mcpSuggestions';
import { skillSuggestionBuilder } from './skillSuggestions';
import { useEffect, useRef, useState } from 'react';
import { EditorEvents } from '../EditorEvents';
import { Markdown } from '@tiptap/markdown';
import { useStore } from '@tomic/react';
import { useSettings } from '../../../helpers/AppSettings';
import Placeholder from '@tiptap/extension-placeholder';
import { useMcpServers } from '@components/AI/MCP/McpServersContext';
import type {
  AtomicResourceSuggestion,
  MCPResourceSuggestion,
  MentionItem,
  SkillSuggestion,
} from './types';
import { Row } from '../../../components/Row';
import {
  IconButton,
  IconButtonVariant,
} from '../../../components/IconButton/IconButton';
import { FaArrowRight } from 'react-icons/fa6';
import { addIf } from '../../../helpers/addIf';
import { useAISettings } from '@components/AI/AISettingsContext';

const createAttribute = (propName: string, dataName: string) => {
  return {
    [propName]: {
      default: null,
      parseHTML: (element: HTMLElement) => element.getAttribute(dataName),
      renderHTML: (attributes: Record<string, unknown>) => {
        if (!attributes[propName]) {
          return {};
        }

        return {
          [dataName]: attributes[propName],
        };
      },
    },
  };
};

const escapeMentionAttribute = (value: unknown): string => {
  return String(value ?? '').replaceAll('"', '&quot;');
};

const SerializableMention = Mention.extend({
  renderMarkdown(node: JSONContent) {
    const id = escapeMentionAttribute(node.attrs?.id);
    const label = escapeMentionAttribute(node.attrs?.label);

    return `[@ id="${id}" label="${label}"]`;
  },
  addAttributes() {
    return {
      ...createAttribute('type', 'data-type'),
      ...createAttribute('serverId', 'data-server-id'),
      ...createAttribute('mimeType', 'data-mime-type'),
      ...createAttribute('id', 'data-id'),
      ...createAttribute('label', 'data-label'),
      ...createAttribute('isA', 'data-is-a'),
    };
  },
});

// A second Mention extension for skill slash-commands. Uses a distinct node
// name so it can coexist with `SerializableMention`.
const SkillMention = Mention.extend({
  name: 'skillMention',
  renderMarkdown(node: JSONContent) {
    const id = escapeMentionAttribute(node.attrs?.id);
    const label = escapeMentionAttribute(node.attrs?.label);

    return `[@ id="${id}" label="${label}" type="skill"]`;
  },
  addAttributes() {
    return {
      ...createAttribute('type', 'data-type'),
      ...createAttribute('id', 'data-id'),
      ...createAttribute('label', 'data-label'),
      ...createAttribute('description', 'data-description'),
    };
  },
});

interface AsyncAIChatInputProps {
  /** A one-time handoff draft; later typing and clearing remain user-owned. */
  prefill?: string;
  hasFiles: boolean;
  disabled?: boolean;
  disableSubmit?: boolean;
  large?: boolean;
  onMentionUpdate: (mentions: MentionItem[]) => void;
  onChange: (markdown: string) => void;
  onSubmit: () => void;
  onCompact?: () => void;
  onEditModel?: () => void;
  onEditAgent?: () => void;
  onFileAdded?: (files: File[]) => void;
  rightAlignedChildren?: React.ReactNode;
  /** Bump this to imperatively move focus into the editor (e.g. after picking a model). */
  focusSignal?: number;
}

const AsyncAIChatInput: React.FC<
  React.PropsWithChildren<AsyncAIChatInputProps>
> = ({
  children,
  hasFiles,
  disabled = false,
  disableSubmit = false,
  large = false,
  onMentionUpdate,
  onChange,
  onSubmit,
  onCompact,
  onEditModel,
  onEditAgent,
  onFileAdded,
  rightAlignedChildren,
  focusSignal,
  prefill,
}) => {
  const store = useStore();
  const { drive } = useSettings();
  const { mcpServers } = useAISettings();
  const [markdown, setMarkdown] = useState('');
  const prefilled = useRef<string | undefined>(undefined);
  const markdownRef = useRef(markdown);
  const onSubmitRef = useRef(onSubmit);
  const onCompactRef = useRef(onCompact);
  const disableSubmitRef = useRef(disableSubmit);
  const onEditModelRef = useRef(onEditModel);
  const onEditAgentRef = useRef(onEditAgent);
  markdownRef.current = markdown;
  onSubmitRef.current = onSubmit;
  onCompactRef.current = onCompact;
  onEditModelRef.current = onEditModel;
  onEditAgentRef.current = onEditAgent;
  disableSubmitRef.current = disableSubmit;

  const { serversWithResources, searchResourcesOfServer } = useMcpServers();

  const editor = useEditor(
    {
      extensions: [
        Markdown.configure({
          markedOptions: {
            gfm: true,
          },
        }),
        StarterKit.extend({
          addKeyboardShortcuts() {
            return {
              Enter: () => {
                // Check if the cursor is in a code block, if so allow the user to press enter.
                // Pressing shift + enter will exit the code block.
                if ('language' in this.editor.getAttributes('codeBlock')) {
                  return false;
                }

                if (disableSubmitRef.current) {
                  return false;
                }

                // The content has to be read from a ref because this callback is not updated often leading to stale content.
                onSubmitRef.current();
                setMarkdown('');
                this.editor.commands.clearContent();

                return true;
              },
            };
          },
        }).configure({
          blockquote: false,
          bulletList: false,
          orderedList: false,
          heading: false,
          listItem: false,
          horizontalRule: false,
          bold: false,
          strike: false,
          italic: false,
        }),
        SerializableMention.configure({
          HTMLAttributes: {
            class: 'ai-chat-mention',
          },
          suggestion: searchSuggestionBuilder(
            store,
            drive,
            mcpServers.filter(server =>
              serversWithResources.includes(server.id),
            ),
            searchResourcesOfServer,
          ),
          renderText({ options, node }) {
            return `${options.suggestion.char}bla${node.attrs.title}`;
          },
        }),
        SkillMention.configure({
          HTMLAttributes: {
            class: 'ai-chat-skill-mention',
          },
          suggestion: {
            char: '/',
            ...skillSuggestionBuilder(
              () => onCompactRef.current?.(),
              () => onEditModelRef.current?.(),
              () => onEditAgentRef.current?.(),
            ),
          },
          renderText({ node }) {
            return `/${node.attrs.label ?? ''}`;
          },
        }),
        Placeholder.configure({
          placeholder: 'Ask me anything, / for commands, @ for context',
        }),
        ...addIf(
          !!onFileAdded,
          FileHandler.configure({
            onDrop: (_currentEditor, files) => {
              onFileAdded!(Array.from(files));
            },
            onPaste: (_currentEditor, files, htmlContent) => {
              if (htmlContent) return false;

              onFileAdded!(Array.from(files));
            },
          }),
        ),
      ],
      autofocus: true,
      content: markdownRef.current,
      contentType: 'markdown',
      editable: !disabled,
      editorProps: {
        handlePaste: (_view, event) => {
          if (!onFileAdded) {
            return false;
          }

          const files = extractImageFilesFromClipboard(event.clipboardData);

          if (files.length === 0) {
            return false;
          }

          onFileAdded(files);

          return true;
        },
      },
    },
    [serversWithResources, searchResourcesOfServer, disabled],
  );

  useEffect(() => {
    if (!prefill || !editor || prefilled.current === prefill) return;
    prefilled.current = prefill;

    if (editor.isEmpty) {
      editor.commands.setContent(prefill, { contentType: 'markdown' });
      markdownRef.current = prefill;
      setMarkdown(prefill);
      onChange(prefill);
    }
  }, [prefill, editor, onChange]);

  // Lets the parent move focus into the editor on demand (e.g. right after the
  // user picks a model) by bumping `focusSignal`.
  useEffect(() => {
    if (!focusSignal) return;

    editor?.commands.focus('end');
  }, [focusSignal, editor]);

  const handleChange = () => {
    const value = editor.getMarkdown();
    setMarkdown(value);
    markdownRef.current = value;
    onChange(value);

    if (!editor) {
      return;
    }

    const mentions = digForMentions(editor.getJSON());
    onMentionUpdate(mentions);
  };

  return (
    <>
      <EditorWrapper hideEditor={false} $large={large}>
        <TiptapContextProvider editor={editor}>
          <EditorContent editor={editor} />
          <EditorEvents onChange={handleChange} />
        </TiptapContextProvider>
      </EditorWrapper>
      <Toolbar justify='space-between'>
        {children}
        <Row center style={{ flexShrink: 0 }}>
          {rightAlignedChildren}
          <IconButton
            disabled={
              disabled || disableSubmit || (markdown.length === 0 && !hasFiles)
            }
            onClick={() => {
              onSubmit();
              setMarkdown('');
              editor?.commands.clearContent();
            }}
            title='Send'
            variant={IconButtonVariant.Fill}
          >
            <FaArrowRight />
          </IconButton>
        </Row>
      </Toolbar>
    </>
  );
};

export default AsyncAIChatInput;

/** Bottom bar of the chat input. Every control in here shares one muted tone. */
const Toolbar = styled(Row)`
  width: 100%;
  min-width: 0;
  overflow: hidden;
  color: ${p => p.theme.colors.textLight};
`;

const EditorWrapper = styled(EditorWrapperBase)<{ $large?: boolean }>`
  padding: ${p => p.theme.size(2)};
  font-size: 16px;
  line-height: 1.5;
  flex: unset !important;
  min-height: ${p => (p.$large ? '8rem' : 'none')};
  .ai-chat-mention {
    background-color: ${p => p.theme.colors.mainSelectedBg};
    color: ${p => p.theme.colors.mainSelectedFg};
    border-radius: 5px;
    padding-inline: ${p => p.theme.size(1)};
  }

  .ai-chat-skill-mention {
    color: ${p => p.theme.colors.main};
  }
`;

function digForMentions(data: JSONContent): MentionItem[] {
  if (data.type === 'mention') {
    return [data.attrs as MCPResourceSuggestion | AtomicResourceSuggestion];
  }

  if (data.type === 'skillMention') {
    return [{ ...(data.attrs as SkillSuggestion), type: 'skill' }];
  }

  if (data.content) {
    return data.content.flatMap(digForMentions);
  }

  return [];
}

const clipboardImageExtensionByMimeType: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'image/avif': 'avif',
  'image/bmp': 'bmp',
  'image/svg+xml': 'svg',
  'image/tiff': 'tiff',
};

function extractImageFilesFromClipboard(
  clipboardData: DataTransfer | null,
): File[] {
  if (!clipboardData) {
    return [];
  }

  return Array.from(clipboardData.items).reduce<File[]>((files, item) => {
    if (item.kind !== 'file' || !item.type.startsWith('image/')) {
      return files;
    }

    const file = item.getAsFile();

    if (!file) {
      return files;
    }

    files.push(file.name ? file : nameClipboardImageFile(file, files.length));

    return files;
  }, []);
}

function nameClipboardImageFile(file: File, index: number): File {
  const extension =
    clipboardImageExtensionByMimeType[file.type] ??
    file.type.replace(/^image\//, '').replace(/\+xml$/, '') ??
    'png';
  const suffix = index === 0 ? '' : `-${index + 1}`;

  return new File([file], `pasted-image${suffix}.${extension}`, {
    type: file.type,
    lastModified: file.lastModified,
  });
}
