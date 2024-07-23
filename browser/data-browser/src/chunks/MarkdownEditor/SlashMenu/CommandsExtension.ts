import { Extension, ReactRenderer } from '@tiptap/react';
import { Suggestion, type SuggestionOptions } from '@tiptap/suggestion';
import tippy, { type Instance } from 'tippy.js';
import {
  CommandList,
  type CommandItem,
  type CommandListProps,
  type CommandListRefType,
} from './CommandList';
import {
  FaCode,
  FaHeading,
  FaImage,
  FaListUl,
  FaParagraph,
  FaQuoteLeft,
} from 'react-icons/fa6';

export const SlashCommands = Extension.create({
  name: 'slashCommands',
  addOptions() {
    return {
      suggestion: {
        char: '/',
        command: ({ editor, range, props }) => {
          props.command({ editor, range });
        },
      },
    };
  },
  addProseMirrorPlugins() {
    return [
      Suggestion({
        editor: this.editor,
        ...this.options.suggestion,
      }),
    ];
  },
});

export const suggestion: Partial<SuggestionOptions> = {
  items: ({ query }: { query: string }): CommandItem[] =>
    [
      {
        title: 'Bullet List',
        icon: FaListUl,
        command: ({ editor, range }) =>
          editor.chain().focus().deleteRange(range).toggleBulletList().run(),
      },
      {
        title: 'Codeblock',
        icon: FaCode,
        command: ({ editor, range }) =>
          editor.chain().focus().deleteRange(range).setNode('codeBlock').run(),
      } as CommandItem,
      {
        title: 'Quote',
        icon: FaQuoteLeft,
        command: ({ editor, range }) =>
          editor.chain().focus().deleteRange(range).setBlockquote().run(),
      } as CommandItem,
      {
        title: 'Image',
        icon: FaImage,
        command: ({ editor, range }) =>
          editor.chain().focus().deleteRange(range).setImage({ src: '' }).run(),
      } as CommandItem,
      {
        title: 'Heading 1',
        icon: FaHeading,
        command: ({ editor, range }) =>
          editor
            .chain()
            .focus()
            .deleteRange(range)
            .setNode('heading', { level: 1 })
            .run(),
      } as CommandItem,
      {
        title: 'Heading 2',
        icon: FaHeading,
        command: ({ editor, range }) =>
          editor
            .chain()
            .focus()
            .deleteRange(range)
            .setNode('heading', { level: 2 })
            .run(),
      } as CommandItem,
      {
        title: 'Heading 3',
        icon: FaHeading,
        command: ({ editor, range }) =>
          editor
            .chain()
            .focus()
            .deleteRange(range)
            .setNode('heading', { level: 3 })
            .run(),
      } as CommandItem,
      {
        title: 'Heading 4',
        icon: FaHeading,
        command: ({ editor, range }) =>
          editor
            .chain()
            .focus()
            .deleteRange(range)
            .setNode('heading', { level: 4 })
            .run(),
      } as CommandItem,
      {
        title: 'Heading 5',
        icon: FaHeading,
        command: ({ editor, range }) =>
          editor
            .chain()
            .focus()
            .deleteRange(range)
            .setNode('heading', { level: 5 })
            .run(),
      } as CommandItem,
      {
        title: 'Heading 6',
        icon: FaHeading,
        command: ({ editor, range }) =>
          editor
            .chain()
            .focus()
            .deleteRange(range)
            .setNode('heading', { level: 6 })
            .run(),
      } as CommandItem,
      {
        title: 'Paragraph',
        icon: FaParagraph,
        command: ({ editor, range }) =>
          editor.chain().focus().deleteRange(range).setNode('paragraph').run(),
      } as CommandItem,
    ].filter(item => item.title.toLowerCase().includes(query.toLowerCase())),

  render: () => {
    let component: ReactRenderer<CommandListRefType, CommandListProps>;
    let popup: Instance[];

    return {
      onStart: props => {
        component = new ReactRenderer(CommandList, {
          props,
          editor: props.editor,
        });

        if (!props.clientRect) {
          return;
        }

        popup = tippy('body', {
          getReferenceClientRect: props.clientRect! as () => DOMRect,
          appendTo: () => document.body,
          content: component.element,
          showOnCreate: true,
          interactive: true,
          trigger: 'manual',
          placement: 'bottom-start',
        });
      },

      onUpdate(props) {
        component.updateProps(props);

        if (!props.clientRect) {
          return;
        }

        popup[0].setProps({
          getReferenceClientRect: props.clientRect as () => DOMRect,
        });
      },

      onKeyDown(props) {
        if (props.event.key === 'Escape') {
          popup[0].hide();

          return true;
        }

        if (!component.ref) {
          return false;
        }

        return component.ref.onKeyDown(props.event);
      },

      onExit() {
        popup[0].destroy();
        component.destroy();
      },
    };
  },
};
