import { localizeText, type LocalizedText } from '@tomic/react';
import { styled } from 'styled-components';
import type { JSX } from 'react';
import { useSettings } from '../helpers/AppSettings';
import { useDeclaredLanguages } from '../hooks/useDeclaredLanguages';

interface LocalizedTextValueProps {
  value: LocalizedText | undefined;
}

/**
 * Renders a LocalizedText value in the app's content language. When that
 * language has no translation, the fallback is shown dimmed with a warning
 * marker instead of silently passing for a translation — so a table column
 * doubles as a completeness audit when switching the content language.
 */
export function LocalizedTextValue({
  value: stored,
}: LocalizedTextValueProps): JSX.Element {
  // A cleared translation is stored as '' by older clients. It is not a
  // deliberate empty translation: treat it as absent, so the fallback and the
  // missing marker come back.
  const value = withoutEmptyTranslations(stored);
  const { contentLanguage } = useSettings();
  const declared = useDeclaredLanguages();

  const primary = contentLanguage.split('-')[0];
  const missing =
    !!value &&
    value[contentLanguage] === undefined &&
    value[primary] === undefined;
  const text = localizeText(value, contentLanguage);

  const presentCount = value ? Object.keys(value).length : 0;
  const missingDeclared =
    declared?.filter(tag => value?.[tag] === undefined) ?? [];

  const title =
    `${presentCount} ${presentCount === 1 ? 'language' : 'languages'}` +
    (missingDeclared.length > 0
      ? `, missing: ${missingDeclared.join(', ')}`
      : '');

  if (missing) {
    return (
      <MissingFallback title={`No ${contentLanguage} translation. ${title}`}>
        {text}
      </MissingFallback>
    );
  }

  return <span title={title}>{text}</span>;
}

const MissingFallback = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-style: italic;

  &::after {
    content: ' ●';
    color: ${p => p.theme.colors.warning};
    font-size: 0.6em;
    vertical-align: super;
  }
`;

function withoutEmptyTranslations(
  value: LocalizedText | undefined,
): LocalizedText | undefined {
  if (!value) {
    return value;
  }

  return Object.fromEntries(
    Object.entries(value).filter(([, text]) => text !== ''),
  );
}
