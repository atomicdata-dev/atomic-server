import CodeMirror, {
  type BasicSetupOptions,
  type ReactCodeMirrorRef,
} from '@uiw/react-codemirror';
import { githubLight, githubDark } from '@uiw/codemirror-theme-github';
import { css as cssLanguage } from '@codemirror/lang-css';
import { linter, lintGutter } from '@codemirror/lint';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from 'styled-components';
import { CodeEditorWrapper } from './CodeEditorWrapper';
import { cssLinter } from './cssLint';

export interface CSSEditorProps {
  labelId?: string;
  initialValue?: string;
  placeholder?: string;
  onChange: (value: string) => void;
}

const basicSetup: BasicSetupOptions = {
  lineNumbers: true,
  foldGutter: false,
  highlightActiveLine: true,
  indentOnInput: true,
};

/**
 * ASYNC COMPONENT DO NOT IMPORT DIRECTLY, USE {@link CSSEditor.tsx}.
 */
const AsyncCSSEditor: React.FC<CSSEditorProps> = ({
  labelId,
  initialValue,
  placeholder,
  onChange,
}) => {
  const editorRef = useRef<ReactCodeMirrorRef>(null);
  const theme = useTheme();
  const [value, setValue] = useState(initialValue ?? '');

  // The compiler can't optimize the CodeMirror component, so this is a
  // callback (same reason as AsyncJSONEditor's).
  const handleChange = useCallback(
    (val: string) => {
      setValue(val);
      onChange(val);
    },
    [onChange],
  );

  const extensions = useMemo(
    () => [cssLanguage(), linter(cssLinter, { delay: 300 }), lintGutter()],
    [],
  );

  useEffect(() => {
    // The actual editor is not mounted immediately so we need to wait a cycle.
    requestAnimationFrame(() => {
      if (editorRef.current?.editor && labelId) {
        const realEditor =
          editorRef.current.editor.querySelector('.cm-content');

        if (!realEditor) {
          return;
        }

        realEditor.setAttribute('aria-labelledby', labelId);
      }
    });
  }, [labelId]);

  return (
    <CodeEditorWrapper>
      <CodeMirror
        ref={editorRef}
        value={value}
        onChange={handleChange}
        placeholder={placeholder}
        // We disable tab indenting because that would mess with accessibility/keyboard navigation.
        indentWithTab={false}
        theme={theme.darkMode ? githubDark : githubLight}
        minHeight='150px'
        maxHeight='30rem'
        maxWidth='100%'
        basicSetup={basicSetup}
        extensions={extensions}
      />
    </CodeEditorWrapper>
  );
};

export default AsyncCSSEditor;
