import type { Extensions } from '@tiptap/core';
import { Link } from './Link';
import { TaskList, TaskItem } from '@tiptap/extension-list';
import TextAlign from '@tiptap/extension-text-align';
import {
  TextStyle,
  Color,
  BackgroundColor,
} from '@tiptap/extension-text-style';
import Typography from '@tiptap/extension-typography';
import { StarterKit } from '@tiptap/starter-kit';
import { TableKit } from '@tiptap/extension-table';
import type { Store } from '@tomic/react';
import {
  ResourceNode,
  ResourceNodeInline,
} from './ResourceExtension/ResourceNode';
import { ExtendedImage } from './ImagePicker';
import { Note } from './NoteExtention/NoteExtention';

export type DocumentCollaborationExtensionOptions = {
  /** When set (e.g. in the live editor), image paste/drop can upload files. */
  uploadImage?: (files: File[]) => Promise<string[]>;
};

const linkExtension = Link.extend({
  parseHTML: () => [
    {
      tag: 'a[href]',
      getAttrs: node => {
        if (node.getAttribute('data-type')) {
          return false;
        }

        return {
          href: node.getAttribute('href'),
          target: node.getAttribute('target'),
        };
      },
    },
  ],
}).configure({
  autolink: true,
  openOnClick: true,
  HTMLAttributes: {
    class: 'tiptap-link',
    rel: 'noopener noreferrer',
    target: '_blank',
  },
});

/**
 * StarterKit through ExtendedImage — same order as before ResourceNode in
 * {@link CollaborativeEditor}.
 */
export function getDocumentCollaborationCoreExtensions(
  options?: DocumentCollaborationExtensionOptions,
): Extensions {
  return [
    StarterKit.configure({
      undoRedo: false,
      link: false,
      codeBlock: {
        enableTabIndentation: true,
      },
    }),
    Note,
    Typography,
    linkExtension,
    ExtendedImage.configure({
      ...(options?.uploadImage ? { uploadImage: options.uploadImage } : {}),
      HTMLAttributes: {
        class: 'tiptap-image',
      },
    }),
  ];
}

/** Resource nodes + alignment, lists, table, colors — follows slash/resource commands in the UI editor. */
export function getDocumentCollaborationResourceAndFormattingExtensions(
  store: Store,
): Extensions {
  return [
    ResourceNode.configure({
      store,
    }),
    ResourceNodeInline.configure({
      store,
    }),
    TextAlign.configure({
      types: ['heading', 'paragraph'],
    }),
    TaskList,
    TaskItem.configure({
      nested: true,
    }),
    TextStyle,
    TableKit,
    Color,
    BackgroundColor,
  ];
}

/**
 * Full extension list for schema.
 */
export function getDocumentCollaborationExtensions(
  store: Store,
  options?: DocumentCollaborationExtensionOptions,
): Extensions {
  return [
    ...getDocumentCollaborationCoreExtensions(options),
    ...getDocumentCollaborationResourceAndFormattingExtensions(store),
  ];
}
