import { useEffect } from 'react';
import { useTipTapEditor } from './TiptapContext';

interface EditorEventsProps {
  onChange?: (content: string) => void;
}

export function EditorEvents({ onChange }: EditorEventsProps): null {
  const editor = useTipTapEditor();

  useEffect(() => {
    if (!editor) return;

    const callback = () => {
      onChange?.(editor.storage.markdown.getMarkdown());
    };

    if (editor) {
      editor.on('update', callback);
    }

    return () => {
      if (editor) {
        editor.off('update', callback);
      }
    };
  }, [editor]);

  return null;
}
