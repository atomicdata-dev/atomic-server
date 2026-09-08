import { describe, expect, it } from 'vitest';
import { EditorState } from '@codemirror/state';
import { cssLinter, MAX_CUSTOM_CSS_BYTES } from './cssLint';
import type { EditorView } from '@uiw/react-codemirror';

/** The linter only reads `view.state.doc`, so a bare EditorState is enough. */
const lint = (doc: string) =>
  cssLinter({ state: EditorState.create({ doc }) } as EditorView);

describe('cssLinter', () => {
  it('passes valid CSS', () => {
    expect(lint('.atomic-form-card { border-radius: 24px }')).toEqual([]);
    expect(lint('')).toEqual([]);
  });

  it('flags a block that is never closed', () => {
    const [diagnostic] = lint('.a { color: red');

    expect(diagnostic?.severity).toBe('error');
    expect(diagnostic?.message).toContain('never closed');
    expect(diagnostic?.from).toBe('.a '.length);
  });

  it('flags a closing brace with no opener', () => {
    const [diagnostic] = lint('.a { color: red } }');

    expect(diagnostic?.message).toContain('without a matching opening one');
    expect(diagnostic?.from).toBe(18);
  });

  it('ignores braces inside comments and strings', () => {
    expect(lint('/* .a { */ .b { color: red }')).toEqual([]);
    expect(lint('.a::after { content: "}" }')).toEqual([]);
    expect(lint(".a::after { content: '{' }")).toEqual([]);
    // A quote escaped inside a string must not end it early.
    expect(lint('.a::after { content: "\\"}" }')).toEqual([]);
  });

  it('flags CSS over the size the server will accept', () => {
    const padding = ' '.repeat(MAX_CUSTOM_CSS_BYTES);
    const [diagnostic] = lint(`.a { color: red }${padding}`);

    expect(diagnostic?.message).toContain('Too long');
  });

  it('counts size in bytes, not characters', () => {
    // Two bytes per char in UTF-8, so half the limit in chars is at the limit.
    const justUnder = 'é'.repeat(MAX_CUSTOM_CSS_BYTES / 2 - 20);

    expect(lint(`.a::after { content: "${justUnder}" }`)).toEqual([]);
    expect(
      lint(`.a::after { content: "${'é'.repeat(MAX_CUSTOM_CSS_BYTES)}" }`),
    ).toHaveLength(1);
  });
});
