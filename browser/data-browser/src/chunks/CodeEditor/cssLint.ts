import type { Diagnostic } from '@codemirror/lint';
import type { EditorView } from '@uiw/react-codemirror';

/** Mirrors `MAX_CUSTOM_CSS_BYTES` in `server/src/forms.rs`. Past it the server
 * drops the stylesheet whole rather than serving half of one, so the editor
 * has to say so before the owner publishes. */
export const MAX_CUSTOM_CSS_BYTES = 50 * 1024;

/**
 * A deliberately small linter for custom CSS.
 *
 * It does not try to validate properties or values — CodeMirror's CSS mode
 * already highlights those, browsers ignore declarations they don't understand,
 * and a stricter linter here would reject valid-but-new syntax the way a stale
 * browser list does. It catches the two failures that actually lose an owner
 * their work: a stylesheet the server will refuse for size, and unbalanced
 * braces, which silently swallow every rule after the mistake.
 */
export function cssLinter(view: EditorView): Diagnostic[] {
  const text = view.state.doc.toString();
  const diagnostics: Diagnostic[] = [];

  const bytes = new TextEncoder().encode(text).length;

  if (bytes > MAX_CUSTOM_CSS_BYTES) {
    diagnostics.push({
      from: 0,
      to: text.length,
      severity: 'error',
      message: `Too long: ${Math.round(bytes / 1024)} KB of CSS, the limit is ${
        MAX_CUSTOM_CSS_BYTES / 1024
      } KB. Longer stylesheets are dropped entirely when the form is served.`,
    });
  }

  const unbalanced = findUnbalancedBrace(text);

  if (unbalanced !== undefined) {
    diagnostics.push({
      from: unbalanced.from,
      to: Math.min(unbalanced.from + 1, text.length),
      severity: 'error',
      message:
        unbalanced.kind === 'unclosed'
          ? 'This block is never closed — everything after it is part of it.'
          : 'Closing brace without a matching opening one.',
    });
  }

  return diagnostics;
}

interface UnbalancedBrace {
  from: number;
  kind: 'unclosed' | 'unopened';
}

/** Scans for the first brace that has no partner, skipping over comments and
 * quoted strings so a `content: "}"` or a commented-out block doesn't read as
 * a mistake. Returns the position of the offending brace — for an unclosed
 * block that is the outermost `{` still open at the end of the document. */
function findUnbalancedBrace(text: string): UnbalancedBrace | undefined {
  const open: number[] = [];
  let i = 0;

  while (i < text.length) {
    const char = text[i];

    if (char === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 2;
      continue;
    }

    if (char === '"' || char === "'") {
      i += 1;

      while (i < text.length && text[i] !== char) {
        // A backslash escapes the next character, including the quote.
        i += text[i] === '\\' ? 2 : 1;
      }

      i += 1;
      continue;
    }

    if (char === '{') {
      open.push(i);
    } else if (char === '}') {
      if (open.length === 0) {
        return { from: i, kind: 'unopened' };
      }

      open.pop();
    }

    i += 1;
  }

  const first = open[0];

  return first === undefined ? undefined : { from: first, kind: 'unclosed' };
}
