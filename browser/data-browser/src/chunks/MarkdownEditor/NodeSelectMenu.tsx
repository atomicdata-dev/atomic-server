import { BasicSelect } from '../../components/forms/BasicSelect';
import { useTipTapEditor } from './TiptapContext';
import type { Editor } from '@tiptap/react';

const getSelectedNode = (editor: Editor): string => {
  if (editor.isActive('codeBlock')) return 'codeBlock';
  if (editor.isActive('heading', { level: 1 })) return 'heading-1';
  if (editor.isActive('heading', { level: 2 })) return 'heading-2';
  if (editor.isActive('heading', { level: 3 })) return 'heading-3';
  if (editor.isActive('heading', { level: 4 })) return 'heading-4';
  if (editor.isActive('heading', { level: 5 })) return 'heading-5';
  if (editor.isActive('heading', { level: 6 })) return 'heading-6';

  return 'paragraph';
};

const nodeData = (name: string): [title: string, level?: number] => {
  if (name.startsWith('heading')) {
    return ['heading', parseInt(name.split('-')[1])];
  }

  return [name];
};

export function NodeSelectMenu(): React.JSX.Element {
  const editor = useTipTapEditor();

  if (!editor) return <></>;

  const selectedNode = getSelectedNode(editor);

  const changeNodeType = (nodeType: string) => {
    const [targetNodeTitle, level] = nodeData(nodeType);
    editor.commands.setNode(targetNodeTitle, level ? { level } : undefined);
  };

  return (
    <BasicSelect
      value={selectedNode}
      disabled={editor.isActive('image')}
      onChange={e => changeNodeType(e.target.value)}
    >
      <option value='paragraph'>Paragraph</option>
      <option value='codeBlock'>Codeblock</option>
      <option value='heading-1'>Heading 1</option>
      <option value='heading-2'>Heading 2</option>
      <option value='heading-3'>Heading 3</option>
      <option value='heading-4'>Heading 4</option>
      <option value='heading-5'>Heading 5</option>
      <option value='heading-6'>Heading 6</option>
    </BasicSelect>
  );
}
