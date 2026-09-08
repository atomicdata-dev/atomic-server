import CodeMirror, {
  hoverTooltip,
  type BasicSetupOptions,
  type EditorView,
  type ReactCodeMirrorRef,
} from '@uiw/react-codemirror';
import { githubLight, githubDark } from '@uiw/codemirror-theme-github';
import { json, jsonParseLinter, jsonLanguage } from '@codemirror/lang-json';
import {
  jsonSchemaLinter,
  jsonSchemaHover,
  jsonCompletion,
  stateExtensions,
  handleRefresh,
} from 'codemirror-json-schema';
import { linter, lintGutter, type Diagnostic } from '@codemirror/lint';
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type RefObject,
} from 'react';
import { styled, useTheme } from 'styled-components';
import type { JSONSchema7 } from 'ai';
import { addIf } from '@helpers/addIf';

export interface JSONEditorProps {
  labelId?: string;
  initialValue?: string;
  showErrorStyling?: boolean;
  schema?: JSONSchema7;
  required?: boolean;
  maxWidth?: string;
  autoFocus?: boolean;
  onChange: (value: string) => void;
  onValidationChange?: (isValid: boolean) => void;
  onBlur?: () => void;
}

const basicSetup: BasicSetupOptions = {
  lineNumbers: true,
  foldGutter: false,
  highlightActiveLine: true,
  indentOnInput: true,
};

type Reports = Record<string, boolean>;

/**
 * ASYNC COMPONENT DO NOT IMPORT DIRECTLY, USE {@link JSONEditor.tsx}.
 */
const AsyncJSONEditor: React.FC<JSONEditorProps> = ({
  labelId,
  initialValue,
  showErrorStyling,
  required,
  maxWidth,
  schema,
  autoFocus,
  onChange,
  onValidationChange,
  onBlur,
}) => {
  const editorRef = useRef<ReactCodeMirrorRef>(null);
  const jsonParserLinterRef = useRef(jsonParseLinter());
  const schemaLinterRef = useRef(jsonSchemaLinter());
  const theme = useTheme();
  const [value, setValue] = useState(initialValue ?? '');
  const [reports, setReports] = useState<Reports>({});

  const reporter = useCallback((key: string, valid: boolean) => {
    setReports(prev => ({ ...prev, [key]: valid }));
  }, []);

  useEffect(() => {
    onValidationChange?.(Object.values(reports).every(Boolean));
  }, [reports, onValidationChange]);

  // We need to use callback because the compiler can't optimize the CodeMirror component.
  const handleChange = useCallback(
    (val: string) => {
      setValue(val);
      onChange(val);
    },
    [onChange],
  );

  const jsonLinter = useHookIntoValidator(
    'json',
    jsonParserLinterRef,
    reporter,
    !!required,
  );
  const schemaLinter = useHookIntoValidator(
    'jsonSchema',
    schemaLinterRef,
    reporter,
    true,
  );

  const extensions = useMemo(
    () => [
      json(),
      linter(jsonLinter, {
        delay: 300,
      }),
      lintGutter(),
      // If a schema is provided we add all the JSON Schema tooling.
      addIf(
        !!schema,
        linter(schemaLinter, {
          needsRefresh: handleRefresh,
        }),
        jsonLanguage.data.of({
          autocomplete: jsonCompletion(),
        }),
        hoverTooltip(jsonSchemaHover()),
        stateExtensions(schema),
      ),
    ],
    [jsonLinter, schemaLinter, schema],
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
    <CodeEditorWrapper
      onBlur={() => onBlur?.()}
      className={showErrorStyling ? 'json-editor__error' : ''}
    >
      <CodeMirror
        ref={editorRef}
        autoFocus={autoFocus}
        value={value}
        onChange={handleChange}
        placeholder='Enter valid JSON...'
        // We disable tab indenting because that would mess with accessibility/keyboard navigation.
        indentWithTab={false}
        theme={theme.darkMode ? githubDark : githubLight}
        minHeight='150px'
        maxHeight='40rem'
        maxWidth={maxWidth ?? '100%'}
        basicSetup={basicSetup}
        extensions={extensions}
      />
    </CodeEditorWrapper>
  );
};

function useHookIntoValidator(
  key: string,
  validator: RefObject<(view: EditorView) => Diagnostic[]>,
  reporter: (key: string, valid: boolean) => void,
  required: boolean,
): (view: EditorView) => Diagnostic[] {
  const lastDiagnostics = useRef<Diagnostic[]>([]);

  const validationLinter = useMemo(() => {
    return (view: EditorView) => {
      const isEmpty = view.state.doc.length === 0;
      let diagnostics = validator.current(view);

      if (!required && isEmpty) {
        diagnostics = [];
      }

      // Compare the diagnostics so we don't call the onValidationChange callback unnecessarily.
      const prev = lastDiagnostics.current;
      const changed =
        diagnostics.length !== prev.length ||
        diagnostics.some(
          (d, i) => d.from !== prev[i]?.from || d.message !== prev[i]?.message,
        );

      if (changed) {
        lastDiagnostics.current = diagnostics;
        reporter(key, diagnostics.length === 0);
      }

      return diagnostics;
    };
  }, [key, validator, reporter, required]);

  return validationLinter;
}

export default AsyncJSONEditor;

const CodeEditorWrapper = styled.div`
  display: contents;

  &.json-editor__error .cm-editor {
    border-color: ${p => p.theme.colors.alert} !important;
  }

  & .cm-editor {
    border: 1px solid ${p => p.theme.colors.bg2};
    border-radius: ${p => p.theme.radius};
    outline: none;

    &:focus-within {
      border-color: ${p => p.theme.colors.main};
    }

    & .cm-scroller {
      min-height: 150px;
    }
  }

  & .cm-tooltip-hover {
    background-color: ${p => p.theme.colors.bg};
    padding: ${p => p.theme.size(2)};
    box-shadow: ${p => p.theme.boxShadowSoft};
    border-radius: ${p => p.theme.radius};
    border: ${p => (p.theme.darkMode ? '1px solid' : 'none')};
    ${p => p.theme.colors.bg2};

    & .cm-tooltip-arrow {
      display: none;
    }
  }

  & .cm-gutters {
    background: ${p => p.theme.colors.bg};
    border-top-left-radius: ${p => p.theme.radius};
    border-bottom-left-radius: ${p => p.theme.radius};
    min-height: 150px;

    & .cm-gutterElement {
      display: grid;
      place-items: center;
    }

    & .cm-lint-marker-error {
      content: '';
      background: ${p => p.theme.colors.alert};
      border-radius: 50%;
      height: 0.5rem;
      width: 0.5rem;
    }
  }

  & .cm-tooltip {
    background-color: ${p => p.theme.colors.bg};
    box-shadow: ${p => p.theme.boxShadowSoft};
    border-radius: ${p => p.theme.radius};
    border: none;

    & > ul > li {
      background-color: none;
      padding: ${p => p.theme.size(2)} !important;
      margin: 0;

      &:first-of-type {
        border-top-left-radius: ${p => p.theme.radius};
        border-top-right-radius: ${p => p.theme.radius};
      }
      &:last-of-type {
        border-bottom-left-radius: ${p => p.theme.radius};
        border-bottom-right-radius: ${p => p.theme.radius};
      }
      &[aria-selected='true'] {
        background-color: ${p => p.theme.colors.mainSelectedBg};
        color: ${p => p.theme.colors.mainSelectedFg};
      }
    }
  }
`;
