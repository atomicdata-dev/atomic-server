import type { Editor } from '@tiptap/react';
import { createContext, useContext } from 'react';

type TiptapContextType = Editor | null;

export const TiptapContext = createContext<TiptapContextType>(null);

export const useTipTapEditor = (): TiptapContextType =>
  useContext(TiptapContext);

interface TipTapContextProviderProps {
  editor: Editor | null;
}

export const TiptapContextProvider = ({
  editor,
  children,
}: React.PropsWithChildren<TipTapContextProviderProps>) => (
  <TiptapContext.Provider value={editor}>{children}</TiptapContext.Provider>
);
