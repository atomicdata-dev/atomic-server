import { styled } from 'styled-components';

/** Chrome shared by the CodeMirror-based editors (`AsyncJSONEditor`,
 * `AsyncCSSEditor`): themes the editor, gutters, lint markers and completion
 * tooltips with the app's own colors. Add `code-editor__error` to show the
 * invalid state. */
export const CodeEditorWrapper = styled.div`
  display: contents;

  &.code-editor__error .cm-editor {
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
