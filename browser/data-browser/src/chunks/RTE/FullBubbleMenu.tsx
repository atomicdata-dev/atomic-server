import { BubbleMenu } from './BubbleMenu';
import { useTipTapEditor } from './TiptapContext';

export const FullBubbleMenu: React.FC = () => {
  const editor = useTipTapEditor();

  // A destroyed editor keeps its `view` — TipTap flips `isDestroyed` instead
  // — so `!editor.view` alone let the menu keep rendering against a dead
  // editor.
  if (!editor.view || editor.isDestroyed) {
    return null;
  }

  return <BubbleMenu />;
};
